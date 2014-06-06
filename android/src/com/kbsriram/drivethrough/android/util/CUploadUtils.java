package com.kbsriram.drivethrough.android.util;

import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Environment;
import android.os.FileObserver;
import android.provider.MediaStore;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.auth.UserRecoverableNotifiedException;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.kbsriram.common.drive.CDrive;
import com.kbsriram.common.pgp.CPGPUtils;
import com.kbsriram.drivethrough.android.db.CDb;
import com.kbsriram.drivethrough.android.db.CLocalImage;
import com.kbsriram.drivethrough.android.db.CMap;
import com.kbsriram.drivethrough.android.event.CStatusEvent;
import com.kbsriram.drivethrough.android.event.CUploadSummaryEvent;
import com.kbsriram.drivethrough.android.receiver.CMaybeUpdateReceiver;
import com.kbsriram.drivethrough.android.service.CTaskQueue;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.DigestOutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import org.bouncyrattle.openpgp.PGPPublicKey;

public class CUploadUtils
{
    public final synchronized static void registerObserver
        (final Context appctx)
    {
        CUtils.LOGD(TAG, "Request-register-observer");

        if (s_observer != null) { return; }

        s_observer = new ContentObserver(null) {
                @Override
                public void onChange(boolean selfChange) {
                    onChange(selfChange, null);
                }
                public void onChange(boolean selfChange, Uri uri) {
                    long now = System.currentTimeMillis();
                    if (now > (s_last_check + MIN_CHECK_INTERVAL_MSEC)) {
                        s_last_check = now;
                        asyncCheck(appctx);
                    }
                }
            };

        appctx.getApplicationContext()
            .getContentResolver()
            .registerContentObserver
            (MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
             true, s_observer);

        // install a daily alarm with minimum power-consumption ramifications,
        // running at 1 minute past midnight, starting with the next day.
        AlarmManager am = (AlarmManager)
            appctx.getSystemService(Context.ALARM_SERVICE);
        if (am == null) { return; }

        PendingIntent pi = PendingIntent.getBroadcast
            (appctx, 0, new Intent(appctx, CMaybeUpdateReceiver.class), 0);

        // First cancel, just to be safe.
        am.cancel(pi);

        // Set up a daily alarm starting at 1:01am the next day
        GregorianCalendar gcset = new GregorianCalendar();
        gcset.add(Calendar.DAY_OF_MONTH, 1);
        gcset.set(Calendar.AM_PM, Calendar.AM);
        gcset.set(Calendar.HOUR, 1);
        gcset.set(Calendar.HOUR_OF_DAY, 1);
        gcset.set(Calendar.MINUTE, 1);
        gcset.set(Calendar.SECOND, 1);
        gcset.set(Calendar.MILLISECOND, 0);

        am.setInexactRepeating
            (AlarmManager.RTC, gcset.getTimeInMillis(),
             AlarmManager.INTERVAL_DAY, pi);

    }

    public final static void asyncCheck(Context ctx)
    {
        CTaskQueue.enqueueNetworkTask(ctx, new CTaskQueue.Task() {
                public void runTask() {
                    try {
                        CUtils.acquireWakeLocks(getContext());
                        syncCheck(getContext(), getDb());
                    }
                    finally {
                        CUtils.releaseWakeLocks();
                    }
                }
            });
    }

    public final static void asyncPublishSummary(Context ctx)
    {
        CTaskQueue.enqueueLocalTask(ctx, new CTaskQueue.Task() {
                public void runTask()
                { syncPublishSummary(getContext(), getDb()); }
            });
    }

    private final static void syncPublishSummary
        (final Context ctx, final CDb cdb)
    {
        long uploaded_count = CLocalImage.getCountByStatus
            (cdb.getDb(), CLocalImage.OK);
        List<CLocalImage> cls = CLocalImage.getByStatus
            (cdb.getDb(), CLocalImage.OK, RECENT_LIMIT);
        List<File> recents = new ArrayList<File>();
        for (CLocalImage cl: cls) {
            recents.add(new File(cl.getPath()));
        }

        long pending_count = -1l;
        List<File> pendings = new ArrayList<File>();
        try {
            crawl(getDcimRoot(), cdb, pendings);
            pending_count = pendings.size();
        }
        catch (IOException ign) {
            CUtils.LOGW(TAG, "Ignoring pending-summary", ign);
        }
        if (pendings.size() > RECENT_LIMIT) {
            List<File> tmp = pendings;
            pendings = new ArrayList<File>();
            for (int i=0; i<RECENT_LIMIT; i++) {
                pendings.add(tmp.get(i));
            }
        }
        CUploadSummaryEvent.publishSummary
            (uploaded_count, recents, pending_count, pendings);
    }

    private final static File getDcimRoot()
    {
        return
            Environment.getExternalStoragePublicDirectory
            (Environment.DIRECTORY_DCIM);
    }

    private final static void syncCheck(final Context ctx, final CDb cdb)
    {
        CUtils.LOGD(TAG, "sync-check");
        // 1. Make a list of files that we need to upload.
        final List<File> tbd = new ArrayList<File>();
        try { crawl(getDcimRoot(), cdb, tbd); }
        catch (IOException ioe) {
            logResult(cdb, "Skip sync - unable to crawl", ioe);
            return;
        }

        if (tbd.size() == 0) {
            CStatusEvent.broadcast("No new pictures");
            return;
        }

        // 2. Now start touching the network if possible.

        if (!CUtils.isWifiAvailable(ctx)) {
            logResult(cdb, "Skip sync - no network available");
            return;
        }

        // This is a rerun of ABaseActivity.ensureGoodies(), except
        // that it runs in the background - so fewer opportunities to
        // fix issues on the fly.
        if (GooglePlayServicesUtil.isGooglePlayServicesAvailable(ctx)
            != ConnectionResult.SUCCESS) {
            logResult(cdb, "Skip sync - play services not available");
            return;
        }
        final String acct = CUtils.getSelectedAccount(ctx);
        if (acct == null) {
            logResult(cdb, "Skip sync - account not selected");
            return;
        }

        String token;

        try {
            token = GoogleAuthUtil.getTokenWithNotification
                (ctx.getApplicationContext(),
                 acct, "oauth2:"+CDrive.SCOPE, null);
        }
        catch (UserRecoverableNotifiedException une) {
            logResult(cdb, "Skip sync - token needs explicit approval");
            // Notification pushed as well.
            return;
        }
        catch (Exception other) {
            logResult(cdb, "Skip sync - failed to get token.", other);
            return;
        }

        CDrive.Credentials cred = new CDrive.Credentials(null, token);
        final CKeyData keys;

        try {
            keys = runCall
                (ctx, acct, cred, new Call<CKeyData>() {
                    public CKeyData run(CDrive.Credentials rcred)
                    throws Exception {
                        return CKeyData.refreshKeys(ctx, cdb, rcred);
                    }
                });
        }
        catch (Exception any) {
            logResult(cdb, "Skip sync - failed to refresh keys.", any);
            return;
        }

        // Finally! now we have a token and keys, start checking if
        // we have files to upload.
        try {
            runCall
                (ctx, acct, cred, new Call<Void>() {
                    public Void run(CDrive.Credentials rcred)
                        throws Exception {
                        doUpload(ctx, cdb, rcred, keys, tbd);
                        return null;
                    }
                });
        }
        catch (Exception any) {
            logResult(cdb, "Sync paused.", any);
        }
    }

    private final static void doUpload
        (Context ctx, CDb cdb, CDrive.Credentials cred,
         CKeyData keys, List<File> tbd)
        throws Exception
    {
        // Get our base-dir.
        CDrive.File remote_root = CDrive.makeOrGetRoot(cred);

        int count = 0;
        File cachedir = ctx.getCacheDir();
        List<PGPPublicKey> encrypt_to = Arrays.asList
            (CPGPUtils.getEncryptionKey
             (keys.getMainKeyRing()));
        for (File src: tbd) {
            // One final check for good luck.
            if (CLocalImage.exists(cdb.getDb(), src.getPath())) {
                continue;
            }

            if (!CUtils.isNetworkAvailable(ctx)) {
                break;
            }

            File tmp = File.createTempFile("drvthru", "gpg", cachedir);
            MessageDigest md = MessageDigest.getInstance("SHA");
            DigestOutputStream dout = null;
            try {
                // 1. Encrypt+sign to tmp file
                CStatusEvent.broadcast("Encrypting "+src);
                dout =
                    new DigestOutputStream
                    (new BufferedOutputStream
                     (new FileOutputStream(tmp)), md);
                CPGPUtils.writeEncryptedSignedData
                    (src, dout, encrypt_to, keys.getDeviceSigningKey(),
                     src.toString(), new Date(src.lastModified()), false);
                dout.close();
                dout = null;

                // 2. Upload.
                String sha = CPGPUtils.toHex(md.digest());
                CStatusEvent.broadcast("Uploading "+sha+".pgp");
                CDrive.upload
                    (cred, tmp, sha+".pgp",
                     CDrive.TYPE_ENCRYPTED, remote_root.getId());

                // 3. Update db.
                CLocalImage.addOrReplace
                    (cdb.getDb(), src.toString(), CLocalImage.OK,
                     src.lastModified(), System.currentTimeMillis());
                count++;
                if ((count % 10) == 0) {
                    asyncPublishSummary(ctx);
                }
            }
            finally {
                // 3. Cleanup.
                if (dout != null) {
                    try { dout.close(); }
                    catch (Throwable ign) {}
                }
                tmp.delete();
            }
        }
        CStatusEvent.broadcast(count+ "files uploaded");
        asyncPublishSummary(ctx);
    }

    private final static void crawl(File root, CDb cdb, List<File> collect)
        throws IOException
    {
        CUtils.LOGD(TAG, "crawling "+root);
        if (!root.isDirectory()) { return; }
        File children[] = root.listFiles();
        if (children == null) { return; }
        for (int i=0; i<children.length; i++) {
            File child = children[i];
            String n = child.getName().toLowerCase();
            if (n.startsWith(".")) { continue; }
            if (child.isDirectory()) {
                crawl(child, cdb, collect);
            }
            else if (child.isFile()) {
                // Check if we've dealt with this before.
                if (!CLocalImage.exists(cdb.getDb(), child.getPath())) {
                    collect.add(child);
                }
            }
        }
    }

    private interface Call<T>
    { public T run(CDrive.Credentials cred) throws Exception; }

    // Attempt to refresh token once.
    private final static <T> T runCall
        (Context ctx, String acct, CDrive.Credentials cred, Call<T> call)
        throws Exception
    {
        try { return call.run(cred); }
        catch (CDrive.ResponseException rex) {
            if (!rex.needsRefresh()) { throw rex; }
            try {
                GoogleAuthUtil.clearToken
                    (ctx.getApplicationContext(), cred.getAccess());
                String token = GoogleAuthUtil.getTokenWithNotification
                    (ctx.getApplicationContext(),
                     acct, "oauth2:"+CDrive.SCOPE, null);
                cred.setAccess(token);
            }
            catch (Exception bypass) {
                throw rex;
            }
            // Try once more.
            return call.run(cred);
        }
    }

    private final static void logResult(CDb cdb, String msg)
    {
        CMap.put(cdb.getDb(), IConstants.KEY_LAST_RESULT, msg);
        CStatusEvent.broadcast(msg);
    }

    private final static void logResult(CDb cdb, String msg, Throwable th)
    {
        StringBuilder sb = new StringBuilder(msg);
        sb.append("\n");
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        th.printStackTrace(pw);
        pw.flush();
        sb.append(sw.toString());
        logResult(cdb, sb.toString());
    }

    private final static String TAG = CUtils.makeLogTag(CUploadUtils.class);
    private final static int RECENT_LIMIT = 6;
    private static ContentObserver s_observer = null;
    private static long s_last_check = 0l;
    private static long MIN_CHECK_INTERVAL_MSEC = 60*1000l;
}

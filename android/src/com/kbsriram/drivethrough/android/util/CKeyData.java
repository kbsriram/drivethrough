package com.kbsriram.drivethrough.android.util;

import android.content.Context;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import com.kbsriram.common.drive.CDrive;
import com.kbsriram.common.pgp.CPGPUtils;
import com.kbsriram.drivethrough.android.db.CDb;
import com.kbsriram.drivethrough.android.db.CMap;
import com.kbsriram.drivethrough.android.event.CKeysAvailableEvent;
import com.kbsriram.drivethrough.android.event.CStatusEvent;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import org.bouncyrattle.openpgp.PGPKeyRing;
import org.bouncyrattle.openpgp.PGPKeyRingGenerator;
import org.bouncyrattle.openpgp.PGPPrivateKey;
import org.bouncyrattle.openpgp.PGPPublicKeyRing;
import org.bouncyrattle.openpgp.PGPSecretKey;
import org.bouncyrattle.openpgp.PGPSecretKeyRing;

public class CKeyData
{
    public final static CKeyData initKeys(Context ctx, String token)
        throws Exception
    { return initKeys(ctx, new CDrive.Credentials(null, token)); }

    // Load any pre-existing keys.
    public final static synchronized CKeyData loadKeys(Context ctx)
        throws Exception
    {
        CKeyData ret = getData();
        // If we got lucky.
        if (ret != null) { return ret; }
        SharedPreferences prefs =
            PreferenceManager.getDefaultSharedPreferences(ctx);

        // 1. Attempt to create or unlock device keys.
        String pw = prefs.getString(IConstants.PREF_DEVICE_PASS, null);
        if (pw == null) { return null; }

        File proot = ctx.getFilesDir();
        File mainpubfile = new File(proot, "main.pkr");
        File devpubfile = new File(proot, "device.pkr");
        File devsecfile = new File(proot, "device.skr");

        if (!mainpubfile.canRead() ||
            !devpubfile.canRead() ||
            !devsecfile.canRead()) {
            return null;
        }

        PGPPrivateKey signpk =
            CPGPUtils.extractPrivateKey
            (CPGPUtils.getSigningKey(readSecret(devsecfile)), pw.toCharArray());

        PGPPublicKeyRing mainpkr = readPublic(mainpubfile);
        return setData(mainpkr, signpk);
    }

    // the full monty - creates new keys as needed.
    public final static synchronized CKeyData initKeys
        (Context ctx, CDrive.Credentials cred)
        throws Exception
    {
        CKeyData ret = getData();
        // If we got lucky.
        if (ret != null) { return ret; }

        File proot = ctx.getFilesDir();
        File mainpubfile = new File(proot, "main.pkr");
        File devpubfile = new File(proot, "device.pkr");
        File devsecfile = new File(proot, "device.skr");
        SharedPreferences prefs =
            PreferenceManager.getDefaultSharedPreferences(ctx);

        // 1. Attempt to create or unlock device keys.
        String pw = prefs.getString(IConstants.PREF_DEVICE_PASS, null);

        if (pw == null) {
            generateAndUploadKeys
                (cred, prefs, devpubfile, devsecfile);
        }
        pw = prefs.getString(IConstants.PREF_DEVICE_PASS, null);

        PGPPrivateKey signpk =
            CPGPUtils.extractPrivateKey
            (CPGPUtils.getSigningKey(readSecret(devsecfile)), pw.toCharArray());

        if (!mainpubfile.canRead()) { downloadMainKey(cred, mainpubfile); }
        PGPPublicKeyRing mainpkr = readPublic(mainpubfile);

        return setData(mainpkr, signpk);
    }

    public final static synchronized CKeyData refreshKeys
        (Context ctx, CDb cdb, CDrive.Credentials cred)
        throws Exception
    {
        CKeyData ret = loadKeys(ctx);
        if ((ret == null) || !CUtils.isWifiAvailable(ctx)) { return ret; }

        // Recheck atmost once a day.
        CMap last = CMap.get(cdb.getDb(), IConstants.KEY_LAST_KEY_REFRESH);
        if ((last != null) &&
            (last.getTimestamp()>(System.currentTimeMillis()-REFRESH_MSEC))) {
                return ret;
        }

        // We have a network - opportunistically compare and update
        // this key as well.

        File proot = ctx.getFilesDir();
        File mainpubfile = new File(proot, "main.pkr");
        File nextmainpubfile = new File(proot, "next_main.pkr");

        downloadMainKey(cred, nextmainpubfile);
        PGPPublicKeyRing nextpkr = readPublic(nextmainpubfile);
        String curfp = CPGPUtils.asFingerprint(ret.getMainKeyRing());
        if (!CPGPUtils.asFingerprint(nextpkr).equals(curfp)) {
            throw new IOException("fingerprints have changed!");
        }
        // update
        saveRing(nextpkr, mainpubfile);
        CMap.put(cdb.getDb(), IConstants.KEY_LAST_KEY_REFRESH, curfp);
        return setData(nextpkr, ret.getDeviceSigningKey());
    }

    private final static void downloadMainKey
        (CDrive.Credentials cred, File out)
        throws Exception
    {
        CStatusEvent.broadcast("refreshing primary key");
        List<CDrive.File> mkeys = CDrive.getMainKeys(cred);
        if (mkeys.size() != 1) {
            throw new IOException("Please install on laptop first");
        }
        CDrive.download
            (new URL(mkeys.get(0).getDownloadUrl()), cred, out);
    }

    private final static void generateAndUploadKeys
        (CDrive.Credentials cred, SharedPreferences prefs,
         File devpubfile, File devsecfile)
        throws Exception
    {
        // Start by getting the root dir, hopefully any token
        // issues will get sorted out right here.
        boolean ok = false;
        try {
            CStatusEvent.broadcast("Fetching drive info");
            CDrive.File remote_root = CDrive.makeOrGetRoot(cred);

            CStatusEvent.broadcast("Generating keys, will take some time.");
            // create and upload a new keypair.
            char[] pwchar = CPGPUtils.genRandom(40);
            PGPKeyRingGenerator pkrg =
                pkrg = CPGPUtils.generateKeyRingGenerator
                ("device-key", pwchar, 0x60);
            PGPPublicKeyRing devpkr = pkrg.generatePublicKeyRing();
            PGPSecretKeyRing devskr = pkrg.generateSecretKeyRing();

            saveRing(devpkr, devpubfile);
            saveRing(devskr, devsecfile);

            CStatusEvent.broadcast("Uploading device key.");
            CDrive.File remote_devpkr = CDrive
                .upload(cred, devpubfile,
                        CPGPUtils.asFingerprint(devpkr)+".pkr",
                        CDrive.TYPE_DEVICE_PUBKEY,
                        remote_root.getId());
            // cool. In theory, we have done all the steps.
            SharedPreferences.Editor editor = prefs.edit();
            editor.putString(IConstants.PREF_DEVICE_PASS, new String(pwchar));
            editor.commit();
            ok = true;
        }
        finally {
            if (!ok) {
                devpubfile.delete();
                devsecfile.delete();
            }
        }
    }

    public final static synchronized CKeyData getData()
    { return s_data; }

    private final static synchronized CKeyData setData
        (PGPPublicKeyRing mainpkr, PGPPrivateKey signpk)
    { return (s_data = new CKeyData(mainpkr, signpk)); }

    private final static PGPPublicKeyRing readPublic(File in)
        throws Exception
    {
        BufferedInputStream bin = null;
        try {
            bin = new BufferedInputStream
                (new FileInputStream(in));
            return CPGPUtils.readPublicKeyRing(bin, true);
        }
        finally {
            if (bin != null) {
                try { bin.close(); }
                catch (IOException ign) {}
            }
        }
    }

    private final static PGPSecretKeyRing readSecret(File in)
        throws Exception
    {
        BufferedInputStream bin = null;
        try {
            bin = new BufferedInputStream
                (new FileInputStream(in));
            return CPGPUtils.readSecretKeyRing(bin);
        }
        finally {
            if (bin != null) {
                try { bin.close(); }
                catch (IOException ign) {}
            }
        }
    }


    private final static void saveRing(PGPKeyRing kr, File out)
        throws IOException
    {
        BufferedOutputStream bout = null;
        try {
            bout =
                new BufferedOutputStream
                (new FileOutputStream(out));
            kr.encode(bout);
            bout.close();
            bout = null;
        }
        finally {
            if (bout != null) {
                try { bout.close(); }
                catch (IOException ign) {}
            }
        }
    }

    private CKeyData
        (PGPPublicKeyRing mainpkr, PGPPrivateKey signpk)
    {
        m_mainpkr = mainpkr;
        m_signpk = signpk;
    }
    public PGPPublicKeyRing getMainKeyRing()
    { return m_mainpkr; }
    public PGPPrivateKey getDeviceSigningKey()
    { return m_signpk; }

    private final PGPPublicKeyRing m_mainpkr;
    private final PGPPrivateKey m_signpk;
    private static CKeyData s_data = null;
    private final static long REFRESH_MSEC = 86400l*1000l;
}

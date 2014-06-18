package com.kbsriram.drivethrough.android.util;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.preference.PreferenceManager;
import android.provider.Settings;
import android.util.Log;
import com.kbsriram.common.drive.CDrive;
import com.kbsriram.drivethrough.android.R;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

public class CUtils
{
    public final static boolean IS_PRODUCTION = false;

    public static synchronized void acquireWakeLocks(Context ctx)
    {
        if (s_wifilock == null) {
            WifiManager wm = (WifiManager)
                ctx.getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                s_wifilock = wm.createWifiLock(TAG);
            }
        }

        if (s_powerlock == null) {
            PowerManager pm = (PowerManager)
                ctx.getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                s_powerlock = pm.newWakeLock
                    (PowerManager.PARTIAL_WAKE_LOCK, TAG);
            }
        }

        if (isWifiAvailable(ctx) && (s_wifilock != null) &&
            !s_wifilock.isHeld()) {
            LOGD(TAG, "acquire wifi lock");
            s_wifilock.acquire();
        }
        if ((s_powerlock != null) && (!s_powerlock.isHeld())) {
            LOGD(TAG, "acquire power lock");
            s_powerlock.acquire();
        }
    }

    public static synchronized void releaseWakeLocks()
    {
        if ((s_wifilock != null) && (s_wifilock.isHeld())) {
            LOGD(TAG, "release wifi lock");
            s_wifilock.release();
        }

        if ((s_powerlock != null) && (s_powerlock.isHeld())) {
            LOGD(TAG, "release power lock");
            s_powerlock.release();
        }
    }

    public static boolean isEnabled(Context ctx)
    {
        SharedPreferences pref = PreferenceManager
            .getDefaultSharedPreferences(ctx);
        return (pref.getBoolean(IConstants.PREF_ENABLED, true));
    }

    public static void setEnabled(Context ctx, boolean v)
    {
        SharedPreferences pref = PreferenceManager
            .getDefaultSharedPreferences(ctx);
        SharedPreferences.Editor editor = pref.edit();
        editor.putBoolean(IConstants.PREF_ENABLED, v);
        editor.commit();
    }

    public static boolean isNetworkAvailable(Context ctx)
    {
        if (!isEnabled(ctx)) { return false; }

        SharedPreferences pref = PreferenceManager
            .getDefaultSharedPreferences(ctx);

        // Check if we want wifi-only
        if (pref.getBoolean(IConstants.PREF_ONLY_WIFI, true)) {
            return isWifiAvailable(ctx);
        }
        else {
            return isAnyNetworkAvailable(ctx);
        }
    }

    public final static String truncate(String s, char c)
    {
        int idx = s.indexOf(c);
        if (idx > 0) { return s.substring(0, idx); }
        else { return s; }
    }

    public final static byte[] getBytes(String s)
    {
        if (s == null) { return null; }
        try { return s.getBytes("utf-8"); }
        catch (UnsupportedEncodingException uee){
            throw new RuntimeException(uee);
        }
    }

    public final static String sha(String in)
    {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return toHex(md.digest(getBytes(in)));
        }
        catch (NoSuchAlgorithmException nse) {
            throw new RuntimeException(nse);
        }
    }

    public final static String toHex(byte[] bytes)
    {
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<bytes.length; i++) {
            int unsignedb = (bytes[i] & 0xff);
            sb.append(TOHEX[(unsignedb>>4)&0xf]);
            sb.append(TOHEX[unsignedb&0xf]);
        }
        return sb.toString();
    }

    public final static Dialog makeAlertDialog
        (final Context ctx, String title, String msg,
         DialogInterface.OnClickListener onclick)
    {
        return
            new AlertDialog.Builder(ctx)
            .setCancelable(false)
            .setTitle(title)
            .setMessage(msg)
            .setNeutralButton(android.R.string.ok, onclick)
            .create();
    }

    public final static Dialog makeYesCancelDialog
        (final Context ctx, int titleid, int msgid, int yesid,
         DialogInterface.OnClickListener onyes,
         DialogInterface.OnClickListener oncancel)
    {
        return
            new AlertDialog.Builder(ctx)
            .setCancelable(true)
            .setTitle(titleid)
            .setMessage(msgid)
            .setNegativeButton(android.R.string.cancel, oncancel)
            .setPositiveButton(yesid, onyes)
            .create();
    }

    public final static Dialog makeEnableWifiDialog
        (final Context ctx, DialogInterface.OnClickListener oncancel)
    {
        AlertDialog.Builder builder = new AlertDialog.Builder(ctx);
        builder
            .setCancelable(false)
            .setTitle(R.string.no_wifi_title)
            .setMessage(R.string.no_wifi_message);

        final Intent wifi_intent=new Intent(Settings.ACTION_WIFI_SETTINGS);
        wifi_intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_WHEN_TASK_RESET);

        if (hasIntent(ctx, wifi_intent)) {
            builder
                .setNegativeButton(android.R.string.cancel, oncancel)
                .setPositiveButton
                (R.string.wifi_settings,
                 new DialogInterface.OnClickListener() {
                     public void onClick(DialogInterface d, int id) {
                         ctx.startActivity(wifi_intent);
                     }
                 });
        }
        else {
            builder
                .setNeutralButton(android.R.string.ok, oncancel);
        }
        return builder.create();
    }
    public final static boolean hasIntent(Context ctx, Intent check)
    {
        List<ResolveInfo> rlist =
            ctx.getPackageManager()
            .queryIntentActivities(check, PackageManager.MATCH_DEFAULT_ONLY);
        return ((rlist != null) && (rlist.size() > 0));
    }

    public final static void setSelectedAccount(Context ctx, String acct)
    {
        SharedPreferences settings =
            PreferenceManager.getDefaultSharedPreferences(ctx);
        SharedPreferences.Editor editor = settings.edit();
        editor.putString(IConstants.PREF_SELECTED_ACCOUNT, acct);
        editor.commit();
    }

    public final static String getSelectedAccount(Context ctx)
    {
        return
            PreferenceManager
            .getDefaultSharedPreferences(ctx)
            .getString(IConstants.PREF_SELECTED_ACCOUNT, null);
    }

    public static boolean isWifiAvailable(Context ctx)
    {
        WifiManager wifi =
            (WifiManager)ctx.getSystemService(Context.WIFI_SERVICE);
        return wifi.isWifiEnabled();
    }

    public static boolean isAnyNetworkAvailable(Context ctx)
    {
        ConnectivityManager cm = (ConnectivityManager)
            ctx.getSystemService(Context.CONNECTIVITY_SERVICE);

        NetworkInfo active = cm.getActiveNetworkInfo();
        return ((active != null) && (active.isConnected()));
    }

    public final static void quietlyClose(Closeable c)
    {
        if (c != null) {
            try { c.close(); }
            catch (Throwable ign) {}
        }
    }

    public static String makeLogTag(Class cls)
    {
        String str = cls.getSimpleName();
        if (str.length() > MAX_LOG_TAG_LENGTH - LOG_PREFIX_LENGTH) {
            return LOG_PREFIX + str.substring
                (0, MAX_LOG_TAG_LENGTH - LOG_PREFIX_LENGTH - 1);
        }
        return LOG_PREFIX + str;
    }

    public static void TLOGD(final String tag, String message)
    {
        if (!IS_PRODUCTION || Log.isLoggable(tag, Log.DEBUG)) {
            Log.d(tag, Thread.currentThread()+": "+message);
        }
    }

    public static void LOGD(final String tag, String message)
    {
        if (!IS_PRODUCTION || Log.isLoggable(tag, Log.DEBUG)) {
            Log.d(tag, message);
        }
    }

    public static void LOGD(final String tag, String message, Throwable cause)
    {
        if (!IS_PRODUCTION || Log.isLoggable(tag, Log.DEBUG)) {
            Log.d(tag, message, cause);
        }
    }

    public static void LOGW(final String tag, String message)
    { Log.w(tag, message); }

    public static void LOGW(final String tag, String message, Throwable cause)
    { Log.w(tag, message, cause); }

    public final static String safeFileName(String s)
    {
        StringBuilder sb = new StringBuilder();
        char[] v = s.toCharArray();
        for (int i=0; i<v.length; i++) {
            char cur = v[i];
            if ((cur >= '0') && (cur <= '9'))
                { sb.append(cur); }
            else if ((cur >= 'A') && (cur <= 'Z'))
                { sb.append(cur); }
            else if ((cur >= 'a') && (cur <= 'z'))
                { sb.append(cur); }
            else if ((cur == '_') || (cur == '.') || (cur == ' '))
                { sb.append(cur); }
            else
                { sb.append('-'); }
        }
        return sb.toString();
    }

    private final static char[] TOHEX = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    private static final String LOG_PREFIX = "drvthru_";
    private static final String TAG = "drivthru_utils";
    private static final int LOG_PREFIX_LENGTH = LOG_PREFIX.length();
    private static final int MAX_LOG_TAG_LENGTH = 23;
    private static volatile WifiManager.WifiLock s_wifilock = null;
    private static volatile PowerManager.WakeLock s_powerlock = null;
    static
    {
        CDrive.setLogger(new CDrive.Logger() {
                public void logd(String tag, String m)
                { LOGD(LOG_PREFIX+tag, m); }
                public void logw(String tag, String m)
                { LOGW(LOG_PREFIX+tag, m); }
                public void logw(String tag, String m, Throwable th)
                { LOGW(LOG_PREFIX+tag, m, th); }
            });
    }
}

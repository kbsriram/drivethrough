package com.kbsriram.drivethrough.android.receiver;

import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.net.NetworkInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.os.Handler;
import com.kbsriram.drivethrough.android.util.CUploadUtils;
import com.kbsriram.drivethrough.android.util.CUtils;

public class CNetworkStateChangeReceiver extends BroadcastReceiver
{
    // This needs to be a quick call
    @Override
    public void onReceive(Context ctx, Intent intent)
    {
        // Take this chance to register alarms and observers
        CUploadUtils.registerObserver(ctx.getApplicationContext());
        if (CUtils.isNetworkAvailable(ctx)) {
            final Handler handler = new Handler();
            final Context appctx = ctx.getApplicationContext();
            handler.postDelayed(new Runnable() {
                    public void run() {
                        CUploadUtils.asyncCheck(appctx);
                    }
                }, NETWORK_DELAY_START_MSEC);
        }
    }

    // 90 seconds.
    private final static long NETWORK_DELAY_START_MSEC = 90*1000l;
}

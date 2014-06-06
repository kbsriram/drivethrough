package com.kbsriram.drivethrough.android.receiver;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import com.kbsriram.drivethrough.android.util.CUploadUtils;
import com.kbsriram.drivethrough.android.util.CUtils;

public class CMaybeUpdateReceiver extends BroadcastReceiver
{
    // This needs to be a quick call
    @Override
    public void onReceive(Context ctx, Intent intent)
    {
        if (CUtils.isWifiAvailable(ctx)) {
            CUploadUtils.asyncCheck(ctx.getApplicationContext());
        }
    }
}

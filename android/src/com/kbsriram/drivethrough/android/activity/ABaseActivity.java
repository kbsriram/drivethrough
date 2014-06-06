package com.kbsriram.drivethrough.android.activity;

import android.accounts.AccountManager;
import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.preference.PreferenceManager;
import com.google.android.gms.auth.GoogleAuthException;
import com.google.android.gms.auth.GoogleAuthUtil;
import com.google.android.gms.auth.GooglePlayServicesAvailabilityException;
import com.google.android.gms.auth.UserRecoverableAuthException;
import com.google.android.gms.common.AccountPicker;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.GooglePlayServicesUtil;
import com.kbsriram.common.drive.CDrive;
import com.kbsriram.drivethrough.android.R;
import com.kbsriram.drivethrough.android.event.CExceptionEvent;
import com.kbsriram.drivethrough.android.event.CKeysAvailableEvent;
import com.kbsriram.drivethrough.android.event.CStatusEvent;
import com.kbsriram.drivethrough.android.service.CTaskQueue;
import com.kbsriram.drivethrough.android.util.CKeyData;
import com.kbsriram.drivethrough.android.util.CUploadUtils;
import com.kbsriram.drivethrough.android.util.CUtils;
import com.kbsriram.drivethrough.android.util.IConstants;

public abstract class ABaseActivity extends Activity
    implements CExceptionEvent.Listener,
               CKeysAvailableEvent.Listener,
               CStatusEvent.Listener
{
    @Override
    protected void onCreate(Bundle bundle)
    {
        super.onCreate(bundle);
        CUploadUtils.registerObserver(getApplicationContext());
    }

    @Override
    protected void onPause()
    {
        CExceptionEvent.unsubscribe(this);
        CStatusEvent.unsubscribe(this);
        CKeysAvailableEvent.unsubscribe(this);
        super.onPause();
    }

    @Override
    protected void onResume()
    {
        super.onResume();
        CExceptionEvent.subscribe(this);
        CStatusEvent.subscribe(this);
        CKeysAvailableEvent.subscribe(this);
        ensureKeys();
    }

    protected abstract void onResumeWithKeys();
    protected abstract void setStatus(String msg, boolean block);

    public void onStatus(CStatusEvent ev)
    { setStatus(ev.getMessage(), m_blocked); }

    public void onKeysAvailable(CKeysAvailableEvent ev)
    { greenLight(); }

    public void onException(CExceptionEvent ev)
    {
        // Handle some common cases right here.
        Throwable th = ev.getCause();
        if (th instanceof CDrive.ResponseException) {
            CDrive.ResponseException cre = (CDrive.ResponseException) th;
            if (cre.needsRefresh()) {
                try {
                    GoogleAuthUtil.clearToken
                        (getApplicationContext(), cre.getAccess());
                }
                catch (Exception bypass) {
                    th = bypass;
                }
                if (th == cre) {
                    m_wait_for_user_auth = false;
                    ensureKeys();
                    return;
                }
            }
        }

        if (th instanceof GooglePlayServicesAvailabilityException) {
            GooglePlayServicesAvailabilityException pex =
                (GooglePlayServicesAvailabilityException) th;
            m_wait_for_play_install = true;
            GooglePlayServicesUtil.getErrorDialog
                (pex.getConnectionStatusCode(),
                 this,
                 IConstants.REQUEST_PLAY_INSTALLED).show();
            return;
        }
        else if (th instanceof UserRecoverableAuthException) {
            UserRecoverableAuthException uae =
                (UserRecoverableAuthException) th;
            m_wait_for_user_auth = true;
            startActivityForResult
                (uae.getIntent(), IConstants.REQUEST_USER_AUTH);
            return;
        }

        // Default - just show it.
        StringBuilder sb = new StringBuilder();
        if (ev.getMessage() != null) {
            sb.append(ev.getMessage());
            sb.append("\n");
        }
        sb.append(ev.getCause().toString());
        showGeneralErrorDialog(sb.toString());
    }

    // Only on UI-thread.
    private void showGeneralErrorDialog(String msg)
    {
        final Bundle bundle = new Bundle();
        bundle.putString(ERROR_MESSAGE, msg);
        showDialog(ERROR_DIALOG, bundle);
    }

    @Override
    protected Dialog onCreateDialog(int id, Bundle bundle)
    {
        switch (id) {

        case ERROR_WIFI_DIALOG:
            return CUtils.makeEnableWifiDialog
                (this, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface d, int id) {
                            d.cancel();
                            removeDialog(id);
                        }
                    });

        case ERROR_DIALOG:
            String msg = bundle.getString(ERROR_MESSAGE);
            if (msg != null) {
                return CUtils.makeAlertDialog
                    (this, "Error", msg,
                     new DialogInterface.OnClickListener() {
                         public void onClick(DialogInterface d, int id) {
                             d.cancel();
                             removeDialog(id);
                         }
                     });
            }
            else {
                return super.onCreateDialog(id, bundle);
            }


        default:
            return super.onCreateDialog(id, bundle);
        }
    }

    protected final void showErrorDialog(Throwable issue)
    {
        CUtils.LOGD(TAG, "Issue", issue);
        showErrorDialog(issue.getMessage());
    }
    protected final void showErrorDialog(String msg)
    {
        final Bundle bundle = new Bundle();
        bundle.putString(ERROR_MESSAGE, msg);
        showDialog(ERROR_DIALOG, bundle);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data)
    {
        CUtils.LOGD(TAG, "on-activity-result-code: "+request);

        switch (request) {

        case IConstants.REQUEST_PLAY_INSTALLED:
            // We see this as the outcome of a play-install.
            m_wait_for_play_install = false;
            m_wait_for_select_account = false;
            m_wait_for_user_auth = false;
            if (result == Activity.RESULT_OK) {
                ensureKeys();
            }
            else {
                // User has asked us to kill ourselves. Oh well.
                setResult(result);
                finish();
            }
            break;

        case IConstants.REQUEST_SELECT_ACCOUNT:
            // when a select-account picker returns.
            m_wait_for_select_account = false;
            m_wait_for_user_auth = false;
            if (result == Activity.RESULT_OK) {
                CUtils.setSelectedAccount
                    (this,data.getStringExtra(AccountManager.KEY_ACCOUNT_NAME));
                ensureKeys();
            }
            else {
                setResult(result);
                finish();
            }
            break;

        case IConstants.REQUEST_USER_AUTH:
            // outcome of an auth-request that can come at any time.
            m_wait_for_user_auth = false;
            if (result == Activity.RESULT_OK) {
                ensureKeys();
            }
            else {
                // kill myself; because auth should always succeed.
                setResult(result);
                finish();
            }
            break;

        default:
            super.onActivityResult(request, result, data);
            break;
        }
    }

    private void greenLight()
    {
        m_blocked = false;
        setStatus(null, true);
        setStatus(null, false);
        onResumeWithKeys();
    }

    // A long list of checks - make sure we have an unlocked keypair,
    // or generate and upload one.
    private void ensureKeys()
    {
        m_blocked = true;
        CUtils.LOGD(TAG, "ensure-goodies");
        // First baseline check play services.
        int code =
            GooglePlayServicesUtil.isGooglePlayServicesAvailable(this);
        if (code != ConnectionResult.SUCCESS) {
            if (m_wait_for_play_install) { return; }
            if (!GooglePlayServicesUtil.isUserRecoverableError(code)) {
                setStatus
                    (GooglePlayServicesUtil.getErrorString(code), true);
                return;
            }
            m_wait_for_play_install = true;
            setStatus("Install play", true);
            GooglePlayServicesUtil
                .getErrorDialog
                (code, this, IConstants.REQUEST_PLAY_INSTALLED)
                .show();
            return;
        }
        CUtils.LOGD(TAG, "play-services-ok");

        // check we've selected an account.
        final String acct = CUtils.getSelectedAccount(this);
        if (acct == null) {
            if (!m_wait_for_select_account) {
                m_wait_for_select_account = true;
                setStatus("Select account", true);
                Intent intent = AccountPicker
                    .newChooseAccountIntent
                    (null, null, new String[]{"com.google"},
                     true, null, null, null, null);
                startActivityForResult
                    (intent, IConstants.REQUEST_SELECT_ACCOUNT);
            }
            return;
        }
        CUtils.LOGD(TAG, "account-selected: "+acct);

        // First short-circuit test to see if we've loaded our keys.
        if (CKeyData.getData() != null) {
            greenLight();
            return;
        }

        CTaskQueue.enqueueLocalTask
            (this.getApplicationContext(),
             new CTaskQueue.Task() {
                 protected void runTask()
                     throws Exception
                 { syncLoadKeys(getContext(), acct); }
             });
    }

    private static void syncLoadKeys(Context ctx, String acct)
        throws Exception
    {
        CKeyData keys = CKeyData.loadKeys(ctx);
        if (keys != null) {
            CKeysAvailableEvent.publishKeys(keys);
            return;
        }
        // Seems like the first time, need to get tokens. This will
        // drop an exception the first time - handled by
        // onExceptionEvent.
        CStatusEvent.broadcast("connect to drive");
        String token = GoogleAuthUtil.getToken
            (ctx.getApplicationContext(), acct, "oauth2:"+CDrive.SCOPE);
        CStatusEvent.broadcast("creating keys");
        keys = CKeyData.initKeys(ctx, token);
        if (keys != null) {
            CKeysAvailableEvent.publishKeys(keys);
        }
    }


    protected final static int ERROR_DIALOG = 100;
    protected final static String ERROR_MESSAGE = "error_msg";
    protected final static int ERROR_WIFI_DIALOG = 101;
    private boolean m_wait_for_play_install = false;
    private boolean m_wait_for_user_auth = false;
    private boolean m_wait_for_select_account = false;
    private boolean m_blocked = true;
    private final static String TAG = CUtils.makeLogTag(ABaseActivity.class);
}

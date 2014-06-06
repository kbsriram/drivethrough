package com.kbsriram.drivethrough.android.activity;

import android.app.Activity;
import android.content.ContentUris;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.BaseColumns;
import android.provider.MediaStore;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.kbsriram.drivethrough.android.R;
import com.kbsriram.drivethrough.android.event.CStatusEvent;
import com.kbsriram.drivethrough.android.event.CUploadSummaryEvent;
import com.kbsriram.drivethrough.android.util.CBitmapUtils;
import com.kbsriram.drivethrough.android.util.CUploadUtils;
import com.kbsriram.drivethrough.android.util.CUtils;
import com.kbsriram.drivethrough.android.view.CRoundedBitmapView;
import com.kbsriram.drivethrough.android.view.CStatusCounterView;
import java.io.File;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CStartActivity extends ABaseActivity
    implements CUploadSummaryEvent.Listener,
               CRoundedBitmapView.Loader,
               CBitmapUtils.BitmapLoadedEvent.Listener

{
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        findViewById(R.id.main_refresh).setOnClickListener
            (new View.OnClickListener() {
                    public void onClick(View v) {
                        CUploadUtils.asyncCheck(getApplicationContext());
                    }
                });
        m_block_status = (TextView) findViewById(R.id.main_status);
        m_content = findViewById(R.id.main_content);
        m_content_status = (TextView) findViewById(R.id.main_content_status);
        m_counter_uploaded = (CStatusCounterView)
            findViewById(R.id.main_counter_uploaded);
        m_counter_pending = (CStatusCounterView)
            findViewById(R.id.main_counter_pending);
        m_recents_tn = (ViewGroup) m_content.findViewById
            (R.id.main_recents);
        m_recents_tv = (TextView) m_content.findViewById
            (R.id.main_recents_title);
        m_pendings_tn = (ViewGroup) m_content.findViewById
            (R.id.main_pendings);
        m_pendings_tv = (TextView) m_content.findViewById
            (R.id.main_pendings_title);

    }

    @Override
    public void onPause()
    {
        clearPendingRequests();
        CBitmapUtils.BitmapLoadedEvent.unsubscribe(this);
        CUploadSummaryEvent.unsubscribe(this);
        super.onPause();
    }

    @Override
    public void onResume()
    {
        CUploadSummaryEvent.subscribe(this);
        CBitmapUtils.BitmapLoadedEvent.subscribe(this);
        super.onResume();
    }

    public void requestBitmap
        (CRoundedBitmapView view, File file, int width, int height)
    {
        addPendingRequest(view, file);
        CBitmapUtils.asyncLoadBitmap
            (getApplicationContext(), file,
             CUtils.safeFileName(file.toString()), width, height);
    }

    public void onBitmapLoaded(CBitmapUtils.BitmapLoadedEvent ev)
    {
        //CUtils.LOGD(TAG, "got bitmap for "+ev.getFile());
        List<CRoundedBitmapView> rbvs = removePendingRequests(ev.getFile());
        if (rbvs != null) {
            for (CRoundedBitmapView rbv: rbvs) {
                rbv.setBitmapFor(ev.getFile(), ev.getBitmap());
            }
        }
    }

    public void onUploadSummary(CUploadSummaryEvent ev)
    {
        int uc = (int) ev.getUploadedCount();
        int pc = (int) ev.getPendingCount();

        m_counter_uploaded.setCounter(uc);
        m_counter_pending.setCounter(pc);

        updateThumbnailGrid(uc, ev.getRecents(), m_recents_tv, m_recents_tn);
        updateThumbnailGrid(pc, ev.getPendings(), m_pendings_tv, m_pendings_tn);

        m_counter_uploaded.postInvalidate();
        m_counter_pending.postInvalidate();
    }

    protected void onResumeWithKeys()
    {
        CUploadUtils.asyncPublishSummary(getApplicationContext());
        CStatusEvent ev = CStatusEvent.getLastEvent();
        if (ev != null) {
            if (ev.getTimestamp() >
                (System.currentTimeMillis() - 60*1000l)) {
                setStatus(ev.getMessage(), false);
            }
        }
    }

    protected void setStatus(String m, boolean block)
    {
        if (block) {
            m_content.setVisibility(View.GONE);
            m_block_status.setVisibility(View.VISIBLE);
            m_block_status.setText(m);
        }
        else {
            m_block_status.setVisibility(View.GONE);
            m_content.setVisibility(View.VISIBLE);
            m_content_status.setText(m);
        }
    }

    private void updateThumbnailGrid
        (int count, List<File> files, TextView tv, ViewGroup vg)
    {
        //CUtils.LOGD(TAG, "count="+count+", files="+files);
        if ((count <= 0) || (files.size() == 0)) {
            tv.setVisibility(View.GONE);
            vg.setVisibility(View.GONE);
            return;
        }

        tv.setVisibility(View.VISIBLE);
        vg.setVisibility(View.VISIBLE);
        int availslots = vg.getChildCount();
        int availfiles = files.size();
        for (int curidx=0; curidx<availslots; curidx++) {
            CRoundedBitmapView bmv = (CRoundedBitmapView) vg.getChildAt(curidx);
            if (curidx >= availfiles) {
                bmv.setVisibility(View.GONE);
                bmv.setOnClickListener(null);
                continue;
            }
            bmv.setVisibility(View.VISIBLE);
            bmv.setLoader(this);
            bmv.setFile(files.get(curidx));
            bmv.setOnClickListener(m_bmv_listener);
        }
    }

    private final void launchThumbnailFile(File file)
    {
        if (file == null) { return; }
        String mime = URLConnection.guessContentTypeFromName(file.toString());
        CUtils.LOGD(TAG, "file: "+file+", mime="+mime);
        if (mime == null) { return; }

        Uri uri = getMediaStoreUriFromFile(file, mime);
        if (uri == null) {
            // try to fallback anyway.
            uri = Uri.fromFile(file);
        }
        else {
            // avoid setting mime if we have a mediastore uri
            mime = null;
        }
        Intent view_intent = new Intent(Intent.ACTION_VIEW, uri);
        if (mime != null) { view_intent.setType(mime); }

        if (CUtils.hasIntent(this, view_intent)) {
            startActivity(view_intent);
        }
        else {
            CUtils.LOGD(TAG, "bubkas on uri: "+uri+", mime="+mime);
        }
    }

    private final Uri getMediaStoreUriFromFile(File path, String mime)
    {
        Uri base;
        if (mime.startsWith("image")) {
            base = MediaStore.Images.Media.EXTERNAL_CONTENT_URI;
        }
        else if (mime.startsWith("video")) {
            base = MediaStore.Video.Media.EXTERNAL_CONTENT_URI;
        }
        else {
            return null;
        }

        String[] projection = {BaseColumns._ID};

        Cursor cursor = getContentResolver()
            .query
            (base, projection,
             MediaStore.MediaColumns.DATA + "=?",
             new String[] {path.toString()}, null);
        if (cursor.moveToFirst()) {
            return ContentUris.withAppendedId(base, cursor.getLong(0));
        }
        else {
            return null;
        }
    }

    private synchronized List<CRoundedBitmapView>
        removePendingRequests(File file)
    { return m_pending_requests.remove(file); }
    private synchronized void clearPendingRequests()
    { m_pending_requests.clear(); }
    private synchronized void addPendingRequest
        (CRoundedBitmapView rbv, File file)
    {
        List<CRoundedBitmapView> rbvs = m_pending_requests.get(file);
        if (rbvs == null) {
            rbvs = new ArrayList<CRoundedBitmapView>();
            m_pending_requests.put(file, rbvs);
        }
        rbvs.add(rbv);
    }

    private View m_content;
    private TextView m_content_status;
    private TextView m_block_status;
    private CStatusCounterView m_counter_uploaded;
    private CStatusCounterView m_counter_pending;
    private ViewGroup m_recents_tn;
    private TextView m_recents_tv;
    private ViewGroup m_pendings_tn;
    private TextView m_pendings_tv;

    private final View.OnClickListener m_bmv_listener =
        new View.OnClickListener() {
            public void onClick(View v) {
                launchThumbnailFile(((CRoundedBitmapView)v).getFile());
            }
        };
    private final Map<File, List<CRoundedBitmapView>> m_pending_requests =
        new HashMap<File, List<CRoundedBitmapView>>();
    private final static String TAG = CUtils.makeLogTag(CStartActivity.class);
}

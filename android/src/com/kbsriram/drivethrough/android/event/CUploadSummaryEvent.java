package com.kbsriram.drivethrough.android.event;

import com.kbsriram.drivethrough.android.db.CLocalImage;
import com.kbsriram.drivethrough.android.util.CUtils;
import java.io.File;
import java.util.List;

public final class CUploadSummaryEvent
    extends AEvent
{
    public interface Listener
        extends AEvent.Listener
    {
        public void onUploadSummary(CUploadSummaryEvent ev);
    }

    public final static void subscribe(final Listener l)
    { doSubscribe(l, CEventBus.EVENT_UPLOAD_SUMMARY); }

    public final static void unsubscribe(final Listener l)
    { doUnsubscribe(l, CEventBus.EVENT_UPLOAD_SUMMARY); }

    public final void publish()
    { doPublish(CEventBus.EVENT_UPLOAD_SUMMARY); }

    protected final void onUpdate(AEvent.Listener l)
    { ((Listener) l).onUploadSummary(this); }

    public final static void publishSummary
        (long nrecents, List<File> recents, long npends, List<File> pends)
    { (new CUploadSummaryEvent(nrecents, recents, npends, pends)).publish(); }

    private CUploadSummaryEvent
        (long nrecents, List<File> recents, long npends, List<File> pends)
    {
        m_nrecents = nrecents;
        m_recents = recents;
        m_npendings = npends;
        m_pendings = pends;
    }
    public long getUploadedCount()
    { return m_nrecents; }
    public long getPendingCount()
    { return m_npendings; }
    public List<File> getRecents()
    { return m_recents; }
    public List<File> getPendings()
    { return m_pendings; }

    private final long m_nrecents;
    private final long m_npendings;
    private final List<File> m_recents;
    private final List<File> m_pendings;
}

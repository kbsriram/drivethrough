package com.kbsriram.drivethrough.android.event;

import com.kbsriram.drivethrough.android.util.CUtils;

public final class CStatusEvent
    extends AEvent
{
    public interface Listener
        extends AEvent.Listener
    {
        public void onStatus(CStatusEvent ev);
    }

    public final static void subscribe(final Listener l)
    { doSubscribe(l, CEventBus.EVENT_STATUS); }

    public final static void unsubscribe(final Listener l)
    { doUnsubscribe(l, CEventBus.EVENT_STATUS); }

    public final void publish()
    { doPublish(CEventBus.EVENT_STATUS); }

    protected final void onUpdate(AEvent.Listener l)
    { ((Listener) l).onStatus(this); }

    public final static CStatusEvent getLastEvent()
    {
        synchronized (CStatusEvent.class) {
            return s_lastevent;
        }
    }

    public final static void broadcast(String msg)
    {
        CStatusEvent ev = new CStatusEvent(msg, System.currentTimeMillis());
        synchronized (CStatusEvent.class) {
            s_lastevent = ev;
        }
        ev.publish();
    }

    private CStatusEvent(String msg, long ts)
    {
        m_msg = msg;
        m_ts = ts;
    }

    public String getMessage()
    { return m_msg; }
    public long getTimestamp()
    { return m_ts; }

    private final String m_msg;
    private final long m_ts;
    private static CStatusEvent s_lastevent = null;
}

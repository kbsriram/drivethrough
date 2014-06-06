package com.kbsriram.drivethrough.android.event;

import com.kbsriram.drivethrough.android.util.CUtils;

public final class CExceptionEvent
    extends AEvent
{
    public interface Listener
        extends AEvent.Listener
    {
        public void onException(CExceptionEvent ev);
    }

    public final static void subscribe(final Listener l)
    { doSubscribe(l, CEventBus.EVENT_EXCEPTION); }

    public final static void unsubscribe(final Listener l)
    { doUnsubscribe(l, CEventBus.EVENT_EXCEPTION); }

    public final void publish()
    { doPublish(CEventBus.EVENT_EXCEPTION); }

    protected final void onUpdate(AEvent.Listener l)
    { ((Listener) l).onException(this); }

    public final static CExceptionEvent logged
        (String msg, Throwable cause)
    {
        CUtils.LOGW(TAG, "publishing: "+msg, cause);
        return new CExceptionEvent(msg, cause);
    }

    private CExceptionEvent(String msg, Throwable cause)
    {
        m_msg = msg;
        m_cause = cause;
    }

    public String getMessage()
    { return m_msg; }

    public Throwable getCause()
    { return m_cause; }

    private final String m_msg;
    private final Throwable m_cause;

    private final static String TAG = CUtils.makeLogTag(CExceptionEvent.class);
}

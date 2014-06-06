package com.kbsriram.drivethrough.android.event;

import com.kbsriram.drivethrough.android.util.CUtils;
import com.kbsriram.drivethrough.android.util.CKeyData;

public final class CKeysAvailableEvent
    extends AEvent
{
    public interface Listener
        extends AEvent.Listener
    {
        public void onKeysAvailable(CKeysAvailableEvent ev);
    }

    public final static void subscribe(final Listener l)
    { doSubscribe(l, CEventBus.EVENT_KEYS_AVAILABLE); }

    public final static void unsubscribe(final Listener l)
    { doUnsubscribe(l, CEventBus.EVENT_KEYS_AVAILABLE); }

    public final void publish()
    { doPublish(CEventBus.EVENT_KEYS_AVAILABLE); }

    protected final void onUpdate(AEvent.Listener l)
    { ((Listener) l).onKeysAvailable(this); }

    public final static void publishKeys(CKeyData data)
    {
        CUtils.LOGW(TAG, "publishing keys");
        (new CKeysAvailableEvent(data)).publish();
    }

    private CKeysAvailableEvent(CKeyData kd)
    { m_kd = kd; }

    public CKeyData getKeys()
    { return m_kd; }

    private final CKeyData m_kd;

    private final static String TAG =
        CUtils.makeLogTag(CKeysAvailableEvent.class);
}

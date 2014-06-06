package com.kbsriram.drivethrough.android.event;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.util.SparseArray;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public abstract class AEvent
{
    public interface Listener {}

    protected final static void doSubscribe(final Listener l, final int id)
    {
        Looper looper = Looper.myLooper();
        if (Looper.getMainLooper() != looper) {
            throw new IllegalStateException
                ("Can only subscribe on main thread");
        }
        doSubscribe(looper, l, id);
    }

    protected final static void doSubscribe
        (final Looper looper, final Listener l, final int id)
    {
        Handler h = removeHandlerFor(l, id);
        if (h != null) {
            CEventBus.unsubscribe(h, id);
        }

        h = new Handler(looper) {
                @Override public void handleMessage(Message m) {
                    if (m.what != id) {
                        throw new IllegalArgumentException
                            ("Unexpected event: "+m.what);
                    }
                    ((AEvent) m.obj).onUpdate(l);
                }
            };
        setHandlerFor(l, id, h);
        CEventBus.subscribe(h, id);
    }

    protected final static void doUnsubscribe(final Listener l, final int id)
    {
        Handler h = removeHandlerFor(l, id);
        if (h != null) {
            CEventBus.unsubscribe(h, id);
        }
    }

    protected final void doPublish(final int id)
    {
        Message m = Message.obtain();
        m.what = id;
        m.obj = this;
        CEventBus.publish(m);
    }

    protected abstract void onUpdate(Listener l);

    private final static Handler removeHandlerFor(Listener l, int id)
    {
        synchronized (s_lmap) {
            SparseArray<Handler> handlers = s_lmap.get(l);
            if (handlers == null) { return null; }
            Handler ret = handlers.get(id);
            if (ret == null) { return null; }
            handlers.remove(id);
            return ret;
        }
    }

    private final static Handler setHandlerFor(Listener l, int id, Handler h)
    {
        synchronized (s_lmap) {
            SparseArray<Handler> handlers = s_lmap.get(l);
            if (handlers == null) {
                handlers = new SparseArray<Handler>();
                s_lmap.put(l, handlers);
            }
            handlers.put(id, h);
            return h;
        }
    }

    private final static Map<Listener, SparseArray<Handler>> s_lmap =
        new HashMap<Listener, SparseArray<Handler>>();
}

package com.kbsriram.drivethrough.android.event;

import android.os.Handler;
import android.os.Message;
import android.util.SparseArray;
import java.util.ArrayList;
import java.util.List;
import com.kbsriram.drivethrough.android.util.CUtils;

public final class CEventBus
{
    public final static int EVENT_EXCEPTION = 1001;
    public final static int EVENT_KEYS_AVAILABLE = 1002;
    public final static int EVENT_STATUS = 1003;
    public final static int EVENT_UPLOAD_SUMMARY = 1004;
    public final static int EVENT_BITMAP_LOADED = 1005;

    public interface Unhandled
    { public void onUnhandled(Message m); }

    public final static void subscribe(Handler handler, int what)
    {
        synchronized (s_map) {
            List<Handler> cur = s_map.get(what);
            if (cur == null) {
                cur = new ArrayList<Handler>();
                s_map.put(what, cur);
            }
            cur.add(handler);
        }
    }

    public final static void unsubscribe(Handler handler, int what)
    {
        synchronized (s_map) {
            List<Handler> cur = s_map.get(what);
            if (cur != null) {
                cur.remove(handler);
            }
            handler.removeMessages(what);
        }
    }

    public final static void publish(Message m)
    { publish(m, null); }

    public final static void publish(Message m, Unhandled uh)
    {
        synchronized (s_map) {
            List<Handler> targets = s_map.get(m.what);
            if ((targets == null) || (targets.size() == 0)) {
                doUnhandled(m, uh);
                return;
            }
            for (Handler h: targets) {
                Message tm = Message.obtain(h);
                tm.what = m.what;
                tm.obj = m.obj;
                h.sendMessage(tm);
            }
        }
    }

    private final static void doUnhandled(Message m, Unhandled uh)
    {
        if (uh == null) {
            CUtils.LOGD
                (TAG, "Unhandled message: what="+m.what+",type="+m.obj);
            return;
        }
        uh.onUnhandled(m);
    }

    private final static SparseArray<List<Handler>> s_map =
        new SparseArray<List<Handler>>();
    private final static String TAG = CUtils.makeLogTag(CEventBus.class);
}

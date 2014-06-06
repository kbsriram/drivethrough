package com.kbsriram.drivethrough.android.service;

import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;
import java.io.IOException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import com.kbsriram.drivethrough.android.db.CDb;
import com.kbsriram.drivethrough.android.event.CExceptionEvent;
import com.kbsriram.drivethrough.android.util.CUploadUtils;

public final class CTaskQueue extends Service
{
    public enum Type { LOCAL, NETWORK };

    public static abstract class Task
        implements Runnable
    {
        protected abstract void runTask() throws Exception;

        protected final Context getContext()
        { return m_ctx; }

        protected final CDb getDb()
        { return m_cdb; }

        public final void run()
        {
            // Handle exceptions consistently here.
            try {

                runTask();
            }
            catch (Throwable th) {
                CExceptionEvent.logged("Unable to run task", th).publish();
            }
            finally {
                CTaskQueue.cleanupTask(this);
            }
        }

        private final void setContext(Context ctx)
        { m_ctx = ctx; }
        private final void setDb(CDb cdb)
        { m_cdb = cdb; }
        private Context m_ctx = null;
        private CDb m_cdb = null;
    }

    public final static void enqueueNetworkTask(Context ctx, Task t)
    { enqueueTask(ctx, t, s_network_q); }

    public final static void enqueueLocalTask(Context ctx, Task t)
    { enqueueTask(ctx, t, s_local_q); }

    private final static void enqueueTask
        (Context ctx, Task t, LinkedBlockingQueue<Runnable> q)
    {
        ensureServiceStarted(ctx);
        try { q.put(t); }
        catch (InterruptedException iex) {
            Log.d(TAG, "Unable to enqueue task", iex);
        }
    }

    public CTaskQueue() {}

    @Override
    public void onCreate()
    {
        super.onCreate();

        // Thread pools that can be configured differently, based on
        // the expected nature of the tasks they process.
        m_network_pool = new TaskPool(1, s_network_q);
        m_local_pool = new TaskPool(1, s_local_q);
        m_network_pool.prestartCoreThread();
        m_local_pool.prestartCoreThread();
        CUploadUtils.registerObserver(getApplicationContext());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startid)
    { return START_STICKY; }

    @Override
    public IBinder onBind(Intent intent)
    { return null; }

    @Override
    public void onDestroy()
    {
        super.onDestroy();

        shutdownPool(m_network_pool);
        shutdownPool(m_local_pool);
        m_network_pool = null;
        m_local_pool = null;
        synchronized (this) {
            if (m_cdb != null) {
                m_cdb.getDb().close();
                m_cdb = null;
            }
        }
        CTaskQueue.setStarted(false);
    }

    private final static void shutdownPool(TaskPool pool)
    {
        // first attempt polite termination, then
        pool.shutdown();
        boolean ok = false;
        try { ok = pool.awaitTermination(1000, TimeUnit.MILLISECONDS); }
        catch (InterruptedException ign) {}
        finally {
            if (!ok) { pool.shutdownNow(); }
        }
    }

    private void setupTask(Task t)
    {
        t.setContext(getApplicationContext());
        synchronized (this) {
            if (m_cdb == null) {
                m_cdb = new CDb(getApplicationContext());
            }
        }
        t.setDb(m_cdb);
    }

    private static void cleanupTask(Task t)
    {
        t.setContext(null);
        t.setDb(null);
    }

    private final static synchronized void ensureServiceStarted(Context ctx)
    {
        if (isStarted()) { return; }
        ctx.startService(new Intent(ctx, CTaskQueue.class));
        setStarted(true);
    }

    private final static synchronized void setStarted(boolean v)
    { s_has_started = v; }

    private final static synchronized boolean isStarted()
    { return s_has_started; }

    private TaskPool m_network_pool = null;
    private TaskPool m_local_pool = null;
    private CDb m_cdb = null;

    private static boolean s_has_started = false;
    private final static LinkedBlockingQueue<Runnable> s_network_q =
        new LinkedBlockingQueue<Runnable>();
    private final static LinkedBlockingQueue<Runnable> s_local_q =
        new LinkedBlockingQueue<Runnable>();

    private final class TaskPool extends ThreadPoolExecutor
    {
        private TaskPool(int count, LinkedBlockingQueue<Runnable> q)
        { super(count, count, 0l, TimeUnit.MILLISECONDS, q); }

        @Override
        protected void beforeExecute(Thread t, Runnable r)
        {
            super.beforeExecute(t, r);
            setupTask((Task) r);
        }
    }

    private final static String TAG = CTaskQueue.class.getName();
}

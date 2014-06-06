package com.kbsriram.drivethrough.android.util;

/**
 * maintain a small cache of files - this is mostly to hold resized
 * images for larger downloaded images.
 */

import android.content.Context;
import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

public class CFileCache
{
    @SuppressWarnings("serial")
    public CFileCache(Context ctx)
    {
        m_cacheroot = new File(ctx.getCacheDir(), "tn");
        m_access_cache = new LinkedHashMap<String,Integer>() {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String,Integer> e) {
                if (size() < MAX_ENTRIES) { return false; }
                CFileCache.this.setNeedsCleanup(true);
                return true;
            }
        };
    }

    public File getFile(String key, int width, int height)
    {
        String fname = CUtils.sha(key);
        synchronized (m_access_cache) {
            File parent = new File(m_cacheroot, ""+width+"x"+height);
            if (!parent.exists()) { parent.mkdirs(); }
            File ret = new File(parent, fname);
            String access_key = ret.toString();
            if (m_access_cache.get(access_key) == null) {
                // add to accessed cache, and cleanup if necessary.
                m_access_cache.put(access_key, Integer.valueOf(0));
                maybeCleanup(parent);
            }
            return ret;
        }
    }

    private void maybeCleanup(File dir)
    {
        // Don't bother cleaning up unless we really mean it.
        if (!needsCleanup()) { return; }
        long now = System.currentTimeMillis();
        if ((now - m_last_cleanup) < MIN_CLEANUP_INTERVAL_MSEC) {
            setNeedsCleanup(false);
            return;
        }

        // Walk the cache tree; deleting anything that we don't find
        // in our access cache. This also has the side-effect of
        // randomizing the access timestamps, sigh.
        cleanupRoot(dir);
        m_last_cleanup = System.currentTimeMillis();
        setNeedsCleanup(false);
    }

    private void cleanupRoot(File dir)
    {
        if (!dir.isDirectory()) { return; }
        File[] children = dir.listFiles();
        for (int i=0; i<children.length; i++) {
            File child = children[i];
            if ((child != null) &&
                child.isFile() &&
                (m_access_cache.get(child.toString()) == null)) {
                CUtils.LOGD(TAG, "delete: "+child);
                child.delete();
            }
        }
    }

    private void setNeedsCleanup(boolean v)
    { m_cleanup = v; }
    private boolean needsCleanup()
    { return m_cleanup; }

    private final File m_cacheroot;
    private final LinkedHashMap<String,Integer> m_access_cache;
    private boolean m_cleanup = false;
    private long m_last_cleanup = 0l;
    private final static long MIN_CLEANUP_INTERVAL_MSEC = 300l*1000l;
    private final static int MAX_ENTRIES = 80;
    private final static String TAG = CUtils.makeLogTag(CFileCache.class);
}

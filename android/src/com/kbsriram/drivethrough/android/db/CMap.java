package com.kbsriram.drivethrough.android.db;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import java.util.LinkedHashMap;
import java.util.Map;

@SuppressWarnings("serial")
public final class CMap
{
    private final static String TABLE = "map";
    private final static String KEY = "mkey";
    private final static String VALUE = "mvalue";
    private final static String TS = "ts";

    private final static String TABLE_CREATE =
        "create table "+TABLE+"("+
        KEY+" text not null,"+
        VALUE+" text not null,"+
        TS+" integer not null,"+
        "primary key ("+KEY+"))";

    private final static String SELECT_BY_KEY =
        "select "+VALUE+","+TS+" from "+TABLE+" where "+KEY+"=?";

    public final static CMap get(SQLiteDatabase db, String key)
    {
        CMap ret;
        synchronized (s_cache) {
            ret = s_cache.get(key);
        }
        if (ret != null) { return ret; }

        Cursor result = db.rawQuery
            (SELECT_BY_KEY, new String[] {key});
        try {
            if (result.moveToNext()) {
                return cache(key, result.getString(0), result.getLong(1));
            }
            else { return null; }
        }
        finally {
            CDb.close(result);
        }
    }

    // return true if the insert worked.
    public final static boolean put
        (SQLiteDatabase db, String key, String value)
    {
        ContentValues cv = new ContentValues();
        long ts = System.currentTimeMillis();
        cv.put(KEY, key);
        cv.put(VALUE, value);
        cv.put(TS, ts);
        boolean ret = db.insertWithOnConflict
            (TABLE, null, cv, SQLiteDatabase.CONFLICT_REPLACE) > 0;
        if (ret) { cache(key, value, ts); }
        else { cache(key, null, 0); }
        return ret;
    }

    final static void makeSchema(SQLiteDatabase db)
    {
        db.execSQL(TABLE_CREATE);
    }

    private final static CMap cache(String k, String v, long ts)
    {
        CMap ret;
        synchronized (s_cache) {
            if (v != null) {
                ret = new CMap(k, v, ts);
                s_cache.put(k, ret);
            }
            else {
                s_cache.remove(k);
                ret = null;
            }
        }
        return ret;
    }

    private CMap(String k, String v, long ts)
    {
        m_k = k;
        m_v = v;
        m_ts = ts;
    }
    public String getKey()
    { return m_k; }
    public String getValue()
    { return m_v; }
    public long getTimestamp()
    { return m_ts; }
    private final String m_k;
    private final String m_v;
    private final long m_ts;

    private final static Map<String, CMap> s_cache =
        (new LinkedHashMap<String, CMap>() {
            @Override protected boolean removeEldestEntry(Map.Entry e) {
                return size() > 25;
            }
        });
}

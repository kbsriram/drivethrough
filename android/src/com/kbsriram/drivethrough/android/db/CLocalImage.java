package com.kbsriram.drivethrough.android.db;

import android.content.ContentValues;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import java.util.ArrayList;
import java.util.List;

public final class CLocalImage
{
    public final static String OK = "ok";
    public final static String SKIP = "skip";
    public final static String FAILED = "failed";

    private final static String TABLE = "local_image";
    private final static String PATH = "path";
    private final static String STATUS = "status";
    private final static String CREATED = "created";
    private final static String UPLOADED = "uploaded";

    private final static String TABLE_CREATE =
        "create table "+TABLE+"("+
        PATH+" text not null,"+
        STATUS+" text not null,"+
        CREATED+" integer not null,"+
        UPLOADED+" integer not null,"+
        "primary key ("+PATH+"))";

    private final static String TABLE_INDEX_UPLOADED =
        "create index "+TABLE+"_"+UPLOADED+"_index on "+
        TABLE+"("+UPLOADED+" desc)";

    private final static String SELECT_COUNT_BY_STATUS =
        "select count(1) from "+TABLE+
        " where "+STATUS+"=?";

    private final static String SELECT_COUNT_BY_PATH =
        "select count(1) from "+TABLE+
        " where "+PATH+"=?";

    private final static String SELECT_FIELDS =
        "select "+
        PATH+","+
        STATUS+","+
        CREATED+","+
        UPLOADED;

    private final static String SELECT_BY_STATUS_LIMIT =
        SELECT_FIELDS+" from "+TABLE+" where "+
        STATUS+"=? order by "+UPLOADED+" desc limit ?";

    public final static long getCountByStatus
        (SQLiteDatabase db, String status)
    {
        return DatabaseUtils.longForQuery
            (db, SELECT_COUNT_BY_STATUS,
             new String[] {status});
    }

    public final static List<CLocalImage> getByStatus
        (SQLiteDatabase db, String status, int limit)
    {
        List<CLocalImage> ret = new ArrayList<CLocalImage>();

        Cursor c = db.rawQuery
            (SELECT_BY_STATUS_LIMIT,
             new String[] {
                status, String.valueOf(limit)
            });
        try {
            while (c.moveToNext()) {
                ret.add(fromCursor(c));
            }
            return ret;
        }
        finally {
            CDb.close(c);
        }
    }

    public final static boolean exists(SQLiteDatabase db, String path)
    {
        return 1l == DatabaseUtils.longForQuery
            (db, SELECT_COUNT_BY_PATH,
             new String[] {path});
    }

    public final static CLocalImage addOrReplace
        (SQLiteDatabase db, String path, String status,
         long created, long uploaded)
    {
        ContentValues cv = new ContentValues();
        cv.put(PATH, path);
        cv.put(STATUS, status);
        cv.put(CREATED, created);
        cv.put(UPLOADED, uploaded);

        long id = db.insertWithOnConflict
            (TABLE, null, cv, SQLiteDatabase.CONFLICT_REPLACE);
        if (id <= 0) { return null; }
        return new CLocalImage
            (path, status, created, uploaded);
    }

    private final static CLocalImage fromCursor(Cursor c)
    {
        return new CLocalImage
            (c.getString(0),
             c.getString(1),
             c.getLong(2),
             c.getLong(3));
    }

    private CLocalImage
        (String path, String status, long created, long uploaded)
    {
        m_path = path;
        m_status = status;
        m_created = created;
        m_uploaded = uploaded;
    }
    public long getCreated()
    { return m_created; }
    public long getUploaded()
    { return m_uploaded; }
    public String getPath()
    { return m_path; }
    public String getStatus()
    { return m_status; }
    private final String m_path;
    private final String m_status;
    private final long m_created;
    private final long m_uploaded;

    final static void makeSchema(SQLiteDatabase db)
    {
        db.execSQL(TABLE_CREATE);
        db.execSQL(TABLE_INDEX_UPLOADED);
    }
}

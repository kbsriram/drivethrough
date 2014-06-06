package com.kbsriram.drivethrough.android.db;

import android.content.Context;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteOpenHelper;
import android.database.sqlite.SQLiteDatabase;
import android.database.SQLException;

public final class CDb
{
    public CDb(Context ctx)
    { m_openhelper = new Helper(ctx); }

    // We always use a writable database.
    public SQLiteDatabase getDb()
    { return m_openhelper.getWritableDatabase(); }

    public final static void close(Cursor cursor)
    {
        if (cursor != null) { cursor.close(); }
    }

    private final Helper m_openhelper;

    private final static class Helper
        extends SQLiteOpenHelper
    {
        private final static String DB_NAME = "drivethrough.db";
        private final static int DB_VERSION = 1;

        private Helper(Context ctx)
        { super(ctx, DB_NAME, null, DB_VERSION); }

        @Override
        public void onCreate(SQLiteDatabase db)
        {
            CMap.makeSchema(db);
            CLocalImage.makeSchema(db);
        }
        @Override
        public void onUpgrade(SQLiteDatabase db, int oldver, int newver)
        {
            throw new IllegalStateException("unexpected version change");
        }
        /* api 11 @Override */
        public void onDowngrade(SQLiteDatabase db, int oldver, int newver)
        {
            throw new IllegalStateException("unexpected version downgrade");
        }
    }
}

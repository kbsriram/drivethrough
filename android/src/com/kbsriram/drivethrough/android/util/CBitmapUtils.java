package com.kbsriram.drivethrough.android.util;

import android.graphics.Canvas;
import android.content.Context;
import android.database.Cursor;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Paint;
import android.graphics.Point;
import android.graphics.PointF;
import android.provider.MediaStore;
import android.text.Layout;
import android.text.StaticLayout;
import android.text.TextPaint;
import android.text.TextUtils;
import com.kbsriram.drivethrough.android.db.CDb;
import com.kbsriram.drivethrough.android.event.AEvent;
import com.kbsriram.drivethrough.android.event.CEventBus;
import com.kbsriram.drivethrough.android.service.CTaskQueue;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class CBitmapUtils
{
    public final static class BitmapLoadedEvent
        extends AEvent
    {
        public interface Listener
            extends AEvent.Listener
        {
            public void onBitmapLoaded(BitmapLoadedEvent ev);
        }

        public final static void subscribe(final Listener l)
        { doSubscribe(l, CEventBus.EVENT_BITMAP_LOADED); }

        public final static void unsubscribe(final Listener l)
        { doUnsubscribe(l, CEventBus.EVENT_BITMAP_LOADED); }

        private final static void publish(String key, File file, Bitmap bm)
        {
            BitmapLoadedEvent ie = new BitmapLoadedEvent(key, file, bm);
            ie.doPublish(CEventBus.EVENT_BITMAP_LOADED);
        }

        protected final void onUpdate(AEvent.Listener l)
        { ((Listener) l).onBitmapLoaded(this); }

        private BitmapLoadedEvent(String key, File file, Bitmap bm)
        {
            m_key = key;
            m_file = file;
            m_bitmap = bm;
        }

        public final String getKey()
        { return m_key; }
        public final File getFile()
        { return m_file; }
        public final Bitmap getBitmap()
        { return m_bitmap; }

        private final String m_key;
        private final File m_file;
        private final Bitmap m_bitmap;
    }

    public final static void asyncLoadBitmap
        (final Context ctx, final File orig, final String key,
         final int width, final int height)
    {
        CTaskQueue.enqueueLocalTask(ctx, new CTaskQueue.Task() {
                protected void runTask() {
                    loadBitmap(getContext(), orig, key, width, height);
                }
            });
    }

    private final static void loadBitmap
        (Context ctx, File orig, String key, int width, int height)
    {
        CFileCache fc = getFileCache(ctx);
        File tnfile = fc.getFile(key, width, height);
        Bitmap ret;
        if (!tnfile.canRead()) {
            // See if we can regenerate from orig
            if (!orig.canRead()) {
                CUtils.LOGD(TAG, "Nothing found at "+orig);
                BitmapLoadedEvent.publish(key, orig, null);
                return;
            }
            if (!centerCrop(orig, width, height, tnfile)) {
                BitmapLoadedEvent.publish(key, orig, null);
                return;
            }
        }

        // At this point, tnfile should be readable.
        BitmapLoadedEvent.publish
            (key, orig, BitmapFactory.decodeFile(tnfile.toString()));
    }

    private final static synchronized CFileCache getFileCache(Context ctx)
    {
        if (s_filecache == null) {
            s_filecache = new CFileCache(ctx.getApplicationContext());
        }
        return s_filecache;
    }

    private final static Point getBitmapSize(File ipath)
    {
        if ((ipath == null) || (!ipath.canRead())) {
            return null;
        }

        Point ret = getCachedBitmapSize(ipath);
        if (ret == null) {
            ret = readBitmapSize(ipath);
        }
        return ret;
    }

    private final static Point getCachedBitmapSize(File f)
    {
        synchronized (s_sizecache) {
            return s_sizecache.get(f);
        }
    }

    private final static Point readBitmapSize(File f)
    {
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = true;

        BitmapFactory.decodeFile(f.toString(), options);
        if ((options.outWidth == 0) ||
            (options.outHeight == 0)) {
            return null;
        }
        Point ret = new Point(options.outWidth, options.outHeight);
        synchronized (s_sizecache) {
            s_sizecache.put(f, ret);
        }
        return ret;
    }

    private final static class CropParams
    {
        private final static CropParams make
            (float src_width, float src_height,
             int target_iwidth, int target_iheight)
        {
            PointF src_size = new PointF(src_width, src_height);
            PointF target_size = new PointF(target_iwidth, target_iheight);
            Point target_isize = new Point(target_iwidth, target_iheight);

            float src_aspect = src_size.x/src_size.y;
            float target_aspect = target_size.x/target_size.y;

            boolean fit_horizontal = (src_aspect < target_aspect);

            // Find an appropriate scaling value that still
            // covers the target region entirely.
            float scale;
            if (fit_horizontal) { scale = target_size.x/src_size.x; }
            else { scale = target_size.y/src_size.y; }

            // Calculate the largest sample_size value that is a power
            // of 2 and keeps both height and width larger than
            // target_width and target_height.
            int sample_size = 1;
            while (scale < 0.5f) {
                scale *= 2;
                sample_size *= 2;
            }

            return
                new CropParams
                (src_size, target_size, target_isize,
                 scale, fit_horizontal, sample_size);
        }
        private CropParams
            (PointF src_size, PointF target_size, Point target_isize,
             float scale, boolean fit_horizontal, int sample_size)
        {
            m_src_size = src_size;
            m_target_size = target_size;
            m_target_isize = target_isize;
            m_scale = scale;
            m_fit_horizontal = fit_horizontal;
            m_sample_size = sample_size;
        }
        private final PointF m_src_size;
        private final PointF m_target_size;
        private final Point m_target_isize;
        private final float m_scale;
        private final boolean m_fit_horizontal;
        private final int m_sample_size;
    }

    private final static Bitmap scaleBitmap(Bitmap bm, CropParams cp)
    {
        int width;
        int height;
        if (cp.m_fit_horizontal) {
            width = cp.m_target_isize.x;
            height = round(bm.getHeight()*cp.m_scale);
        }
        else {
            width = round(bm.getWidth()*cp.m_scale);
            height = cp.m_target_isize.y;
        }
        return Bitmap.createScaledBitmap(bm, width, height, true);
    }

    private final static Bitmap cropBitmap(Bitmap bm, CropParams cp)
    {
        if (cp.m_fit_horizontal) {
            // top-crop height
            if (bm.getHeight() > cp.m_target_isize.y) {
                bm = Bitmap.createBitmap
                    (bm, 0, 0, cp.m_target_isize.x, cp.m_target_isize.y);
            }
        }
        else {
            // center-crop width
            if (bm.getWidth() > cp.m_target_isize.x) {
                int xoff = (bm.getWidth() - cp.m_target_isize.x)/2;
                bm = Bitmap.createBitmap
                    (bm, xoff, 0, cp.m_target_isize.x, cp.m_target_isize.y);
            }
        }
        return bm;
    }

    private final static boolean centerCrop
        (File src, int width, int height, File dest)
    {
        if ((src == null) || (!src.canRead())) { return false; }

        if (looksLikeImage(src)) {
            return centerCropImage(src, width, height, dest);
        }
        else {
            return centerCropFile(src, width, height, dest);
        }
    }

    private final static boolean looksLikeImage(File src)
    {
        String n = src.getName().toLowerCase();
        return (n.endsWith(".jpg") ||
                n.endsWith(".png") ||
                n.endsWith(".gif"));
    }

    private final static boolean centerCropFile
        (File src, int width, int height, File dest)
    {
        Bitmap preview = Bitmap.createBitmap
            (width, height, Bitmap.Config.ARGB_8888);
        Canvas c = new Canvas(preview);
        c.drawColor(0xffc1c186);
        String name = src.getName();
        TextPaint textpaint = new TextPaint
            (Paint.ANTI_ALIAS_FLAG|Paint.SUBPIXEL_TEXT_FLAG);
        textpaint.setColor(0xcc000000);
        textpaint.setTextSize(((float)height)/4f);

        StaticLayout sl = new StaticLayout
            (name, 0, name.length(), textpaint, width,
             Layout.Alignment.ALIGN_NORMAL, 1f, 0f, true,
             TextUtils.TruncateAt.MIDDLE, width);
        sl.draw(c);
        return writeBitmap(preview, dest);
    }

    private final static boolean centerCropImage
        (File src, int width, int height, File dest)
    {
        Point size = getBitmapSize(src);
        if (size == null) { return false; }

        CropParams cp = CropParams.make(size.x, size.y, width, height);

        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inJustDecodeBounds = false;
        options.inSampleSize = cp.m_sample_size;

        Bitmap destbm;
        try {
            destbm = BitmapFactory.decodeFile(src.toString(), options);
        } catch (OutOfMemoryError ome) {
            CUtils.LOGD
                (TAG, "OOM: "+src+",size="+size+",ss="+cp.m_sample_size);
            return false;
        }

        if (destbm == null) {
            CUtils.LOGD(TAG, "woops -- unable to decode: "+src);
            return false;
        }

        // final adjustments.
        destbm = scaleBitmap(destbm, cp);
        destbm = cropBitmap(destbm, cp);

        return writeBitmap(destbm, dest);
    }

    private final static boolean writeBitmap(Bitmap src, File dest)
    {
        BufferedOutputStream bout = null;
        boolean ok = false;
        try {
            bout =
                new BufferedOutputStream
                (new FileOutputStream(dest), 8192);
            src.compress(Bitmap.CompressFormat.JPEG, 80, bout);
            ok = true;
            return true;
        }
        catch (IOException ioe) {
            CUtils.LOGW(TAG, "Unable to write "+dest, ioe);
            return false;
        }
        finally {
            CUtils.quietlyClose(bout);
            if (!ok) {
                dest.delete();
            }
        }
    }

    private final static int round(float f)
    { return (int) (0.5f+ f); }

    private final static CLruCache<File,Point> s_sizecache =
        new CLruCache<File,Point>(15);
    private static CFileCache s_filecache = null;
    private final static String[] PATH_PROJECTION = {
        MediaStore.Images.Media.DATA
    };
    private final static String TAG = CUtils.makeLogTag(CBitmapUtils.class);
}

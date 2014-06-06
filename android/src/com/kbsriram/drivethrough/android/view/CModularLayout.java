package com.kbsriram.drivethrough.android.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import com.kbsriram.drivethrough.android.R;

public class CModularLayout extends ViewGroup
{
    public CModularLayout(Context ctx, AttributeSet attrs)
    {
        super(ctx, attrs);

        TypedArray a = ctx.obtainStyledAttributes
            (attrs, R.styleable.CModularLayout);
        boolean divider_enabled;
        try {
            m_hspacing = a.getDimensionPixelSize
                (R.styleable.CModularLayout_horizontalSpacing, 0);
            m_vspacing = a.getDimensionPixelSize
                (R.styleable.CModularLayout_verticalSpacing, 0);
            m_modulewidth = a.getDimensionPixelSize
                (R.styleable.CModularLayout_moduleWidth, 60);
            m_moduleheight = a.getDimensionPixelSize
                (R.styleable.CModularLayout_moduleHeight, 60);
            divider_enabled = a.getBoolean
                (R.styleable.CModularLayout_dividerEnabled, false);
        }
        finally {
            a.recycle();
        }
        if (divider_enabled) {
            m_dividerpaint = new Paint();
            m_dividerpaint.setStyle(Paint.Style.STROKE);
            m_dividerpaint.setColor
                (ctx.getResources().getColor(R.color.divider_color));
            m_dividerpath = new Path();
            setWillNotDraw(false);
        }
        else {
            m_dividerpaint = null;
            m_dividerpath = null;
            setWillNotDraw(true);
        }
    }

    @Override
    protected void onMeasure(int wspec, int hspec)
    {
        int wsize = MeasureSpec.getSize(wspec)
            - getPaddingRight() - getPaddingLeft();

        int ncols = wsize/m_modulewidth;
        if (ncols == 0) {
            ncols = 1;
        }

        float module_available =
            (float)wsize - (float)(ncols-1)*m_hspacing;

        float stretchwidth = module_available/ncols;

        m_stretchwidth = round(stretchwidth);

        int cwspec = MeasureSpec.makeMeasureSpec
            (m_stretchwidth, MeasureSpec.EXACTLY);
        int chspec = MeasureSpec.makeMeasureSpec
            (m_moduleheight, MeasureSpec.EXACTLY);

        final int count = getChildCount();
        float curx = getPaddingLeft();
        int cury = getPaddingTop();
        int curcol = 0;

        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() == GONE) { continue; }
            measureChild(child, cwspec, chspec);
            LayoutParams lp = (LayoutParams) child.getLayoutParams();

            lp.x = round(curx);
            lp.y = cury;

            curcol++;
            if (curcol >= ncols) {
                curcol = 0;
                cury += (m_moduleheight+m_vspacing);
                curx = getPaddingLeft();
            }
            else {
                curx += (stretchwidth + m_hspacing);
            }
        }

        wsize += (getPaddingRight()+getPaddingRight());
        int hsize = cury + getPaddingBottom();
        if (curcol == 0) {
            // exact fit.
        }
        else {
            // add an extra row
            hsize += (m_moduleheight+m_vspacing);
        }

        setMeasuredDimension
            (resolveSize(wsize, wspec),
             resolveSize(hsize, hspec));
    }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b)
    {
        final int count = getChildCount();
        if (m_dividerpath != null) { m_dividerpath.reset(); }
        int lastx = 0;
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() == View.GONE) { continue; }
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            child.layout
                (lp.x, lp.y,
                 lp.x + child.getMeasuredWidth(),
                 lp.y + child.getMeasuredHeight());

            if (m_dividerpath == null) { continue; }

            // Update divider path
            if (lp.x != 0) {
                // Not at left edge - so add a suitable vertical line.
                float gap = m_hspacing/2f;
                m_dividerpath.moveTo(lp.x - gap, lp.y + gap);
                m_dividerpath.lineTo
                    (lp.x - gap, lp.y + child.getMeasuredHeight() - gap);
            }
            if (lp.y != 0) {
                float cury = lp.y - m_vspacing/2f;

                if (lp.x == 0) {
                    m_dividerpath.moveTo(0, cury);
                    m_dividerpath.lineTo(child.getMeasuredWidth(), cury);
                }
                else {
                    m_dividerpath.moveTo(lastx, cury);
                    m_dividerpath.lineTo(lp.x + child.getMeasuredWidth(), cury);
                }
            }
            lastx = lp.x + child.getMeasuredWidth();
        }
    }

    @Override
    protected void onDraw(Canvas c)
    {
        super.onDraw(c);
        if (m_dividerpath != null) {
            c.drawPath(m_dividerpath, m_dividerpaint);
        }
    }

    @Override
    protected boolean checkLayoutParams(ViewGroup.LayoutParams p)
    { return p instanceof LayoutParams; }

    @Override
    protected LayoutParams generateDefaultLayoutParams()
    {
        return new LayoutParams
            (LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
    }

    @Override
    public LayoutParams generateLayoutParams(AttributeSet attrs)
    { return new LayoutParams(getContext(), attrs); }

    @Override
    protected LayoutParams generateLayoutParams(ViewGroup.LayoutParams p)
    { return new LayoutParams(p.width, p.height); }

    private int m_hspacing;
    private int m_vspacing;
    private int m_modulewidth;
    private int m_stretchwidth;
    private int m_moduleheight;
    private final Path m_dividerpath;
    private final Paint m_dividerpaint;

    private final static int round(float v)
    { return (int) (v + 0.5f); }

    public static class LayoutParams extends ViewGroup.LayoutParams
    {
        int x;
        int y;

        public LayoutParams(Context ctx, AttributeSet attrs)
        { super(ctx, attrs); }

        public LayoutParams(int w, int h)
        { super(w, h); }
    }
}

package com.kbsriram.drivethrough.android.view;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import com.kbsriram.drivethrough.android.R;
import com.kbsriram.drivethrough.android.util.CUtils;

public class CMaximumWidthLayout extends ViewGroup
{
    public CMaximumWidthLayout(Context ctx, AttributeSet attrs)
    {
        super(ctx, attrs);

        TypedArray a = ctx.obtainStyledAttributes
            (attrs, R.styleable.CMaximumWidthLayout);
        try {
            m_max_child_width = a.getDimensionPixelSize
                (R.styleable.CMaximumWidthLayout_maximumChildWidth, 0);
            m_child_gravity = a.getInt
                (R.styleable.CMaximumWidthLayout_childGravity, CG_CENTER);
        }
        finally {
            a.recycle();
        }
    }

    @Override
    protected void onMeasure(int wspec, int hspec)
    {
        int wmode = MeasureSpec.getMode(wspec);
        int wsize = MeasureSpec.getSize(wspec);

        if (wmode != MeasureSpec.EXACTLY) {
            throw new IllegalArgumentException
                ("MaximumWidthLayout only works for match_parent widths");
        }

        // CUtils.LOGD(TAG, "wspec="+MeasureSpec.toString(wspec));
        int maxw;
        if (m_max_child_width > 0) {
            maxw = m_max_child_width + getPaddingLeft() + getPaddingRight();
        }
        else {
            maxw = 0;
        }

        int cwspec;
        int lo = getPaddingLeft();

        if ((maxw == 0) || (wsize <= maxw)) {
            cwspec = wspec;
        }
        else {
            cwspec = MeasureSpec.makeMeasureSpec
                (maxw, MeasureSpec.EXACTLY);
            lo += (wsize - maxw)/2;
        }
        int targetw =
            MeasureSpec.getSize(cwspec) - getPaddingLeft() - getPaddingRight();

        final int count = getChildCount();
        int maxh = 0;
        //CUtils.LOGD(TAG, "lo="+lo+",targetw="+targetw+
        //            ",maxw="+maxw+",wsize="+wsize+
        //            ",pleft="+getPaddingLeft()+",pright="+getPaddingRight());

        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() == GONE) { continue; }

            measureChild(child, cwspec, hspec);
            final LayoutParams lp = (LayoutParams) child.getLayoutParams();
            int cw = child.getMeasuredWidth();
            // CUtils.LOGD(TAG, "c-"+i+" cw="+cw);
            lp.m_x = lo;
            final int extra = targetw - cw;
            if (extra > 0) {
                switch (m_child_gravity) {
                case CG_CENTER:
                    lp.m_x += extra/2;
                    break;
                case CG_RIGHT:
                    lp.m_x += extra;
                    break;
                default:
                    // left - do nothing
                    break;
                }
            }
            // CUtils.LOGD(TAG, "final-lo="+lp.m_x+" (extra="+extra+")");
            int ch = child.getMeasuredHeight()
                + getPaddingTop() + getPaddingBottom();
            if (ch > maxh) { maxh = ch; }
        }

        setMeasuredDimension
            (wsize, resolveSize(maxh, hspec));
    }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b)
    {
        final int count = getChildCount();
        for (int i = 0; i < count; i++) {
            View child = getChildAt(i);
            if (child.getVisibility() == View.GONE) { continue; }
            LayoutParams lp = (LayoutParams) child.getLayoutParams();
            //CUtils.LOGD(TAG, "child width: "+lp.m_x+"->"+
            //            (lp.m_x+child.getMeasuredWidth()));
            child.layout
                (lp.m_x, getPaddingTop(),
                 lp.m_x + child.getMeasuredWidth(),
                 getPaddingTop() + child.getMeasuredHeight());
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

    private final int m_max_child_width;
    private final int m_child_gravity;

    public static class LayoutParams extends ViewGroup.LayoutParams
    {
        private int m_x;

        public LayoutParams(Context ctx, AttributeSet attrs)
        { super(ctx, attrs); }

        public LayoutParams(int w, int h)
        { super(w, h); }
    }

    private final static int CG_CENTER = 0;
    private final static int CG_LEFT = 1;
    private final static int CG_RIGHT = 2;
    private final static String TAG =
        CUtils.makeLogTag(CMaximumWidthLayout.class);
}

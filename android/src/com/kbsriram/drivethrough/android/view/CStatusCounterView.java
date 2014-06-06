package com.kbsriram.drivethrough.android.view;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.util.AttributeSet;
import android.view.View;
import java.text.NumberFormat;
import com.kbsriram.drivethrough.android.R;
import com.kbsriram.drivethrough.android.util.CUtils;

public class CStatusCounterView extends View
{
    public CStatusCounterView(Context ctx, AttributeSet attrs)
    {
        super(ctx, attrs);
        m_nf = NumberFormat.getInstance();
        m_nf.setGroupingUsed(true);
        Resources res = ctx.getResources();
        m_disabledcolor = res.getColor(R.color.gray);

        TypedArray a = ctx.obtainStyledAttributes
            (attrs, R.styleable.CStatusCounterView);
        try {
            m_activecolor = a.getColor
                (R.styleable.CStatusCounterView_activeColor,
                 m_disabledcolor);
            m_caption = a.getString
                (R.styleable.CStatusCounterView_captionText);
        }
        finally {
            a.recycle();
        }
        m_captionpaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        m_captionpaint.setTextAlign(Paint.Align.CENTER);
        m_captionpaint.setTextSize(res.getDimension(R.dimen.text_size_small));
        m_captionpaint.setColor(m_disabledcolor);
        m_counterpaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        m_counterpaint.setTextAlign(Paint.Align.CENTER);
        m_counterpaint.setColor(m_disabledcolor);
    }

    public void setCounter(int v)
    {
        if (v <= 0) {
            m_captionpaint.setColor(m_disabledcolor);
            m_counterpaint.setColor(m_disabledcolor);
        }
        else {
            m_captionpaint.setColor(m_activecolor);
            m_counterpaint.setColor(m_activecolor);
        }
        if (v < 0) {
            m_counter = "-";
        }
        else {
            m_counter = m_nf.format(v);
        }
    }

    @Override
    protected void onLayout(boolean changed, int l, int t, int r, int b)
    {
        m_width = r-l;
        m_height = b-t;
        // Condensed text character
        // width is approximately 2/3 its size, and
        // I want space for 5 characters. So, set text
        // size = width/(2/3)/5 = ~width*0.3
        m_counterpaint.setTextSize(m_width*0.3f);
        m_caption_y = m_height - m_captionpaint.getTextSize()/2f;
        m_counter_y = (m_height - m_captionpaint.getTextSize()*1.5f)/2f;
        m_cx = m_width/2f;
    }

    @Override
    protected void onMeasure(int wspec, int hspec)
    {
        if ((MeasureSpec.getMode(wspec) != MeasureSpec.EXACTLY) ||
            (MeasureSpec.getMode(hspec) != MeasureSpec.EXACTLY)) {
            throw new IllegalArgumentException("I need exact dimensions.");
        }
        setMeasuredDimension
            (MeasureSpec.getSize(wspec), MeasureSpec.getSize(hspec));
    }

    @Override
    protected void onDraw(Canvas canvas)
    {
        super.onDraw(canvas);

        if ((m_width < 0) || (m_height < 0)) {
            return;
        }

        // caption
        if (m_caption != null) {
            canvas.drawText(m_caption, m_cx, m_caption_y, m_captionpaint);
        }

        // counter
        if (m_counter != null) {
            canvas.drawText
                (m_counter, m_cx, m_counter_y, m_counterpaint);
        }
    }

    private final Paint m_captionpaint;
    private final Paint m_counterpaint;
    private final int m_activecolor;
    private final int m_disabledcolor;
    private final String m_caption;

    private int m_width = -1;
    private int m_height = -1;
    private float m_cx;
    private float m_caption_y;
    private float m_counter_y;
    private String m_counter = "-";
    private final NumberFormat m_nf;
    private final static String TAG =
        CUtils.makeLogTag(CStatusCounterView.class);
}

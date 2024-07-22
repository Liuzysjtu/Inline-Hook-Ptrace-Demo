package com.example.ibored;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import com.example.ibored.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    public TextView resultTextView;         //正中间结果文本框
    public Button loadEvilModuleButton;     //该button是给内存读写用

    /**
     * 每秒自动更新结果文本框，调用native的UpdateResult函数获取tip串
     */
    void updateText() {
        resultTextView.postDelayed(new Runnable() {
            @Override
            public void run() {
                resultTextView.setText(UpdateResult());
                updateText();
            }
        }, 1000);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //加载应用自身的功能so
        System.loadLibrary("IBored");

        resultTextView = (TextView)findViewById(R.id.textViewResult);
        loadEvilModuleButton = (Button)findViewById(R.id.loadButton);
//        loadEvilModuleButton.setOnClickListener(this);

        //开始刷新结果文本框
        resultTextView.setText("Hi");
        updateText();
    }

    /**
     * inline hook测试
     * @param v
     */
//    @Override
//    public void onClick(View v) {
//        System.loadLibrary("InlineHook");
//        loadEvilModuleButton.setEnabled(false);
//    }



    //native功能函数，更新结果文本框字符串
    public static native String UpdateResult();
}
/*
 * ApkSignKiller
 * Copyright 2025 Puruliaking007
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.fixtorv.apksignkiller.activities;

import android.app.AlertDialog;
import android.app.AlertDialog.Builder;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.appcompat.widget.AppCompatImageView;
import androidx.appcompat.widget.AppCompatRadioButton;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.appcompat.widget.Toolbar;

import com.fixtorv.apksignkiller.App;
import com.fixtorv.apksignkiller.R;
import com.fixtorv.apksignkiller.databinding.ActivityMainBinding;
import com.fixtorv.apksignkiller.utils.BinSignKiller;
import com.fixtorv.apksignkiller.utils.FileUtils;
import com.fixtorv.apksignkiller.utils.MTSignKiller;
import com.fixtorv.apksignkiller.utils.MyAppInfo;
import com.github.angads25.filepicker.model.DialogConfigs;
import com.github.angads25.filepicker.model.DialogProperties;
import com.github.angads25.filepicker.view.FilePickerDialog;

import java.io.File;

public class MainActivity extends AppCompatActivity {
    private ActivityMainBinding binding;
	
	
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // Inflate and get instance of binding
        binding = ActivityMainBinding.inflate(getLayoutInflater());

        // set content view to binding's root
        setContentView(binding.getRoot());
		
		Toolbar toolbar = (Toolbar)binding.toolbar;
		setSupportActionBar(toolbar);
		
		if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) { //API 23+
            if (checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED || checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(new String[] {android.Manifest.permission.READ_EXTERNAL_STORAGE,android.Manifest.permission.WRITE_EXTERNAL_STORAGE}, 100);
            } else {
                reqStoragePermission();
            }
        }
		
		binding.apkPath.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence p1, int p2, int p3, int p4) {
            }

            @Override
            public void onTextChanged(CharSequence p1, int p2, int p3, int p4) {
            }

            @Override
            public void afterTextChanged(Editable p1) {
                if (!p1.toString().isEmpty()) {
                    File apk = new File(p1.toString());
                    if (apk.exists()) {
                        binding.apkIcon.setImageDrawable(new MyAppInfo(App.getContext(), apk.getAbsolutePath()).getIcon());
                        binding.apkName.setText(MyAppInfo.getAppName());
                        binding.apkPackage.setText(MyAppInfo.getPackage());
                    } else {
                        binding.apkIcon.setImageResource(R.mipmap.ic_launcher);
                        binding.apkName.setText("Select apk");
                        binding.apkPackage.setText("none");
                    }
                }
            }
        });
		
		binding.browseApk.setOnClickListener(v -> { 
			apkImportDialog(); 
		});
		
		binding.signKillerType.setOnCheckedChangeListener((group, checkedId) -> {
			if (checkedId == R.id.signKillerTypeMT) {
			    App.getPreferences().edit().putBoolean("signKillerTypeMT", true).apply();
                App.getPreferences().edit().putBoolean("signKillerTypeBIN", false).apply();
            } else if (checkedId == R.id.signKillerTypeBin) {
                App.getPreferences().edit().putBoolean("signKillerTypeMT", false).apply();
                App.getPreferences().edit().putBoolean("signKillerTypeBIN", true).apply();
            }
		});
		
		binding.hookRun.setOnClickListener(v -> {
			if (!new File(binding.apkPath.getText().toString()).exists()) return;
			if (App.getPreferences().getBoolean("signKillerTypeMT", true)) {
				new MTSignKiller(this, binding.apkPath.getText().toString()).execute();
            } else {
				new BinSignKiller(this, binding.apkPath.getText().toString()).execute();
            }
		});
    }
	
    
    @Override
    protected void onDestroy() {
        super.onDestroy();
        this.binding = null;
    }
	
	@Override
    public boolean onCreateOptionsMenu(Menu menu) {
		menu.add(0, 0, 0, "GitHub");
		menu.add(0, 1, 1, "Exit");
        return true;
    }
	
	@Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
			case 0:
                Intent intent = new Intent(Intent.ACTION_VIEW);
                intent.setData(Uri.parse("https://github.com/PuruliaKing007/ApkSignKiller"));
                startActivity(intent);
				break;
            case 1:
				finish();
                break;
            default:
                return super.onOptionsItemSelected(item);
        }
        return true;
    }
	
	
	private void reqStoragePermission() {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R && !Environment.isExternalStorageManager()) { // Android 11+ (API 30+)
            AlertDialog dialog = new AlertDialog.Builder(this)
            .setTitle("Android 11 R changes")
            .setMessage("Android 11 introduce a new file-management way called \"Scoped Storage\". You need to grant a special permission!")
            .setPositiveButton("OK", (dia, which) -> {
                Intent intent = new Intent("android.settings.MANAGE_APP_ALL_FILES_ACCESS_PERMISSION");
                intent.setData(Uri.parse(new StringBuffer().append("package:").append(getPackageName()).toString()));
                try {
                    startActivity(intent);
                } catch (ActivityNotFoundException e) {
                    e.printStackTrace();
                    startActivity(new Intent("android.settings.MANAGE_ALL_FILES_ACCESS_PERMISSION"));
                }
            })
			
            .setNegativeButton("CANCLE", null)
            .setNeutralButton("NOT REMIND", (dia, which) -> {
                App.getPreferences().edit().putBoolean("permissionNotRemind", true).apply();
            })
            .create();
            if (App.getPreferences().getBoolean("permissionNotRemind", false) != true) {
                dialog.show();
            }
        }
    }
	
	@Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == 100) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                toast("Storage permission granted");
                reqStoragePermission();
            } else {
                toast("Storage permission denied!");
            }
        }
    }
	
	private void toast(String message) {
		Toast.makeText(this, message, 0).show();
	}
	
	private void apkImportDialog() {
		DialogProperties properties = new DialogProperties();
        properties.selection_mode = DialogConfigs.SINGLE_MODE;
        properties.selection_type = DialogConfigs.FILE_SELECT;
        properties.root = new File(Environment.getExternalStorageDirectory().getAbsolutePath());
        properties.error_dir = new File(DialogConfigs.DEFAULT_DIR);
        properties.offset = new File(DialogConfigs.DEFAULT_DIR);
        properties.extensions = new String[]{"apk", "APK"};
        FilePickerDialog  fpdialog = new FilePickerDialog(this, properties);
        fpdialog.setProperties(properties);
        fpdialog.setTitle("Select Apk");
        fpdialog.setPositiveBtnName("Select");
        fpdialog.setNegativeBtnName("Cancel");
        fpdialog.setDialogSelectionListener(files -> {
            for (int i = 0; i < files.length; ++i) {
                File file1 = new File(files[i]);
				if (file1.getName().endsWith(".apk") || file1.getName().endsWith(".APK")) {
					binding.apkPath.setText(file1.getAbsolutePath());
				} else {
					toast("'Error!!");
				}
            }         
                
        });
        fpdialog.show();      
    }
}

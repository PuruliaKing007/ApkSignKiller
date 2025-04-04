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

package com.fixtorv.apksignkiller.utils;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.graphics.drawable.Drawable;
import android.util.Base64;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MyAppInfo {
    private static PackageManager pm;
    private static PackageInfo pi;

    public MyAppInfo(@NotNull Context c, String apkpath) {
        pm = c.getPackageManager();
        pi = pm.getPackageArchiveInfo(apkpath, 0);
        pi.applicationInfo.sourceDir = apkpath;
        pi.applicationInfo.publicSourceDir = apkpath;
    }

    @NotNull
    public static String getAppName() {
        return (String) pi.applicationInfo.loadLabel(pm);
    }

    @Contract(pure = true)
    public static String getPackage() {
        return pi.applicationInfo.packageName;
    }

    @Contract(pure = true)
    public static String getVName() {
        return pi.versionName;
    }

    @Contract(pure = true)
    public static int getVCode() {
        return pi.versionCode;
    }

    @NotNull
    public static String getSignature() {
        String res = "";
        try {
            @SuppressLint("PackageManagerGetSignatures") PackageInfo packageInfo = pm.getPackageInfo(
                    pi.packageName, PackageManager.GET_SIGNATURES);
            for (Signature signature : packageInfo.signatures) {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA");
                messageDigest.update(signature.toByteArray());
                res = Base64.encodeToString(messageDigest.digest(), Base64.DEFAULT);
            }
        } catch (PackageManager.NameNotFoundException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return res.trim();
    }

    public Drawable getIcon() {
        return pi.applicationInfo.loadIcon(pm);
    }

    public boolean isDebug() {
        return ((pi.applicationInfo.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0);
    }
}
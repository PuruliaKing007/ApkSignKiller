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

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.os.AsyncTask;
import android.util.Base64;

import bin.util.StreamUtil;
import bin.xml.decode.AXmlDecoder;
import bin.xml.decode.AXmlResourceParser;
import bin.xml.decode.XmlPullParser;
import bin.zip.ZipEntry;
import bin.zip.ZipFile;
import bin.zip.ZipOutputStream;

import com.PuruliaCheatz.apksigner.utils.Signer;
import com.fixtorv.apksignkiller.R;

import java.io.PrintWriter;
import org.apache.commons.io.IOUtils;
import org.jetbrains.annotations.NotNull;
import org.jf.baksmali.Baksmali;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedClassDef;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.dexbacked.raw.ItemType;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.writer.builder.DexBuilder;
import org.jf.dexlib2.writer.io.MemoryDataStore;
import org.jf.smali.Smali;
import org.jf.smali.SmaliOptions;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BinSignKiller extends AsyncTask<Void, String, String> {

	private ProgressDialog pd;
    private boolean customApplication = false;
	private String customApplicationName;
    private Context mContext;
    private String srcApk;
	private String outApk;
	private String packageName;
	private String signatures;
    private String tempApk;
	
	public BinSignKiller(Context context, String srcApk) {
        this.mContext = context;
		this.srcApk = srcApk;
        this.outApk = srcApk.replace(".apk", "_unsigned.apk");
        this.tempApk = new File(srcApk).getParentFile().toString() + "/.temp";
    }

    @Override
    protected void onPreExecute() {
        super.onPreExecute();
        pd = new ProgressDialog(mContext);
        pd.setTitle("Patching...");
        pd.setMessage("Waiting for patch...");
        pd.setCancelable(false);
        pd.setIndeterminate(true);
        pd.show();
    }

    @Override
    protected String doInBackground(Void... voids) {
        try {
            Kill();
            publishProgress("Signing APK...");
            new Signer().calculateSignature(outApk, outApk.replace("_unsigned", "_kill"));
            new File(outApk).delete();
			
            return "Path: " + srcApk.toString().replace(".apk", "_kill.apk");
        } catch (IOException e) {
            return "IOException: " + e.getMessage();
        } catch (Exception e) {
            return "Exception: " + e.getMessage();
        }
    }

    @Override
    protected void onProgressUpdate(String... values) {
        super.onProgressUpdate(values);
        pd.setMessage(values[0]);
    }

    @Override
    protected void onPostExecute(String result) {
        super.onPostExecute(result);
        pd.dismiss();
        finished(result);
    }

    @Override
    protected void onCancelled() {
        super.onCancelled();
        pd.dismiss();
    }
	
	private void Kill() throws IOException, Exception {
        new File(outApk).delete();
        publishProgress("Reading signature...");

        byte[] buffer = new byte[8192];
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);

        try (JarFile jarFile = new JarFile(srcApk)) {
            JarEntry jarEntry = jarFile.getJarEntry("AndroidManifest.xml");

            if (jarEntry != null) {
                try (InputStream inputStream = jarFile.getInputStream(jarEntry)) {
                    while (inputStream.read(buffer) != -1) {
                    }
                }

                Certificate[] certificates = jarEntry.getCertificates(); // Fetch certificates

                if (certificates != null) {
                    dataOutputStream.write(certificates.length);
                    for (Certificate cert : certificates) {
                        byte[] encoded = cert.getEncoded();
                        dataOutputStream.writeInt(encoded.length);
                        dataOutputStream.write(encoded);
                    }

                    signatures =
                            Base64.encodeToString(byteArrayOutputStream.toByteArray(), 0)
                                    .replace("\n", "\\n");
                } else {
                    throw new Exception("No signature found");
                }
            } else {
                throw new Exception("AndroidManifest.xml not found");
            }
        } catch (Exception e) {
            throw new Exception("Certificate is null");
        }

        publishProgress("Reading APK...");
        ZipFile zipFile = new ZipFile(srcApk);
        publishProgress("Processing AndroidManifest.xml...");
        ZipEntry manifestEntry = zipFile.getEntry("AndroidManifest.xml");
        byte[] manifestData = parseManifest(zipFile.getInputStream(manifestEntry));

        ZipEntry dexEntry = zipFile.getEntry("classes.dex");
        DexBackedDexFile dex =
                DexBackedDexFile.fromInputStream(
                        Opcodes.getDefault(),
                        new BufferedInputStream(zipFile.getInputStream(dexEntry)));
        publishProgress("Processing classes.dex...");
        byte[] processDex = processDex(dex);

        
        ZipOutputStream zipOutputStream = new ZipOutputStream(new File(tempApk));
        zipOutputStream.setLevel(1);
        Enumeration<ZipEntry> entries = zipFile.getEntries();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            String name = ze.getName();
            if ((name.startsWith("classes") && name.endsWith("dex")) || name.startsWith("./")) {
                zipOutputStream.copyZipEntry(ze, zipFile);
            }
        }
        zipOutputStream.close();
		
		
        ZipOutputStream zos = new ZipOutputStream(new File(outApk));
        publishProgress("Adding modified AndroidManifest.xml...");
        zos.putNextEntry("AndroidManifest.xml");
        zos.write(manifestData);
        zos.closeEntry();
		
        publishProgress("Adding modified classes.dex...");
        zos.putNextEntry("classes.dex");
        zos.write(processDex);
        zos.closeEntry();
		
		
        Enumeration<ZipEntry> enumeration = zipFile.getEntries();
        while (enumeration.hasMoreElements()) {
            ZipEntry ze = enumeration.nextElement();
            if (ze.getName().equals("AndroidManifest.xml")
                    || ze.getName().equals("classes.dex")
                    || ze.getName().startsWith("META-INF/")) continue;
            publishProgress("Adding files: " + ze.getName());
            zos.copyZipEntry(ze, zipFile);
        }
        new File(tempApk).delete();
        zipFile.close();
		zos.close();
    }

    private byte[] processDex(DexBackedDexFile dex) throws Exception {
        DexBuilder dexBuilder = new DexBuilder(Opcodes.getDefault());
        try (InputStream fis = mContext.getAssets().open("PmsHookApplication.smali")) {
            String src = new String(StreamUtil.readBytes(fis), StandardCharsets.UTF_8);
            if (customApplication) {
                if (customApplicationName.startsWith(".")) {
                    if (packageName == null)
                        throw new NullPointerException("Package name is null.");
                    customApplicationName = packageName + customApplicationName;
                }
                customApplicationName = "L" + customApplicationName.replace('.', '/') + ";";
                src = src.replace("Landroid/app/Application;", customApplicationName);
            }
            if (signatures == null)
                throw new NullPointerException("Signatures is null");
            src = src.replace("### Signatures Data ###", signatures).replace("$package_name$", packageName);
            ClassDef classDef = Smali.assembleSmaliFile(src, dexBuilder, new SmaliOptions());
            if (classDef == null)
                throw new Exception("Parse smali failed");
            for (DexBackedClassDef dexBackedClassDef : dex.getClasses()) {
                dexBuilder.internClassDef(dexBackedClassDef);
            }
        }
        MemoryDataStore store = new MemoryDataStore();
        dexBuilder.writeTo(store);
        return Arrays.copyOf(store.getBufferData(), store.getSize());
    }


	private byte[] parseManifest(InputStream is) throws IOException {
        AXmlDecoder axml = AXmlDecoder.decode(is);
        AXmlResourceParser parser = new AXmlResourceParser();
        parser.open(new ByteArrayInputStream(axml.getData()), axml.mTableStrings);
        boolean success = false;

        int type;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
            if (type != XmlPullParser.START_TAG)
                continue;
            if (parser.getName().equals("manifest")) {
                int size = parser.getAttributeCount();
                for (int i = 0; i < size; ++i) {
                    if (parser.getAttributeName(i).equals("package")) {
                        packageName = parser.getAttributeValue(i);
                    }
                }
            } else if (parser.getName().equals("application")) {
                int size = parser.getAttributeCount();
                for (int i = 0; i < size; ++i) {
                    if (parser.getAttributeNameResource(i) == 0x01010003) {
                        customApplication = true;
                        customApplicationName = parser.getAttributeValue(i);
                        int index = axml.mTableStrings.getSize();
                        byte[] data = axml.getData();
                        int off = parser.currentAttributeStart + 20 * i;
                        off += 8;
                        FileUtils.writeInt(data, off, index);
                        off += 8;
                        FileUtils.writeInt(data, off, index);
                    }
                }
                if (!customApplication) {
                    int off = parser.currentAttributeStart;
                    byte[] data = axml.getData();
                    byte[] newData = new byte[data.length + 20];
                    System.arraycopy(data, 0, newData, 0, off);
                    System.arraycopy(data, off, newData, off + 20, data.length - off);

                    // chunkSize
                    int chunkSize = FileUtils.readInt(newData, off - 32);
                    FileUtils.writeInt(newData, off - 32, chunkSize + 20);
                    // attributeCount
                    FileUtils.writeInt(newData, off - 8, size + 1);

                    int idIndex = parser.findResourceID(0x01010003);
                    if (idIndex == -1)
                        throw new IOException("idIndex == -1");

                    boolean isMax = true;
                    for (int i = 0; i < size; ++i) {
                        int id = parser.getAttributeNameResource(i);
                        if (id > 0x01010003) {
                            isMax = false;
                            if (i != 0) {
                                System.arraycopy(newData, off + 20, newData, off, 20 * i);
                                off += 20 * i;
                            }
                            break;
                        }
                    }
                    if (isMax) {
                        System.arraycopy(newData, off + 20, newData, off, 20 * size);
                        off += 20 * size;
                    }

                    FileUtils.writeInt(newData, off, axml.mTableStrings.find("http://schemas.android.com/apk/res/android"));
                    FileUtils.writeInt(newData, off + 4, idIndex);
                    FileUtils.writeInt(newData, off + 8, axml.mTableStrings.getSize());
                    FileUtils.writeInt(newData, off + 12, 0x03000008);
                    FileUtils.writeInt(newData, off + 16, axml.mTableStrings.getSize());
                    axml.setData(newData);
                }
                success = true;
                break;
            }
        }
        if (!success)
            throw new IOException();
        ArrayList<String> list = new ArrayList<>(axml.mTableStrings.getSize());
        axml.mTableStrings.getStrings(list);
        list.add("cc.binmt.signature.PmsHookApplication");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        axml.write(list, baos);
        return baos.toByteArray();
    }
	
	public void finished(String message) {
        AlertDialog.Builder alertDialog = new AlertDialog.Builder(mContext);
        alertDialog.setTitle("Processing completed");
        alertDialog.setCancelable(true);
        alertDialog.setMessage(message);
        alertDialog.setPositiveButton("OK", null);
        alertDialog.show();
    }
}

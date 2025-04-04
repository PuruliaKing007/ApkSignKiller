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

import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
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

import org.jf.baksmali.Baksmali;
import org.jf.baksmali.BaksmaliOptions;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedClassDef;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.writer.builder.DexBuilder;
import org.jf.dexlib2.writer.io.MemoryDataStore;
import org.jf.smali.Smali;
import org.jf.smali.SmaliOptions;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class MTSignKiller extends AsyncTask<Void, String, String> {
	
	private ProgressDialog pd;
    private boolean customApplication = false;
	private String customApplicationName;
    private Context mContext;
    private String srcApk;
	private String outApk;
	private String packageName;
	private String signatures;
	
	public MTSignKiller(Context context, String srcApk) {
        this.mContext = context;
		this.srcApk = srcApk;
        this.outApk = srcApk.replace(".apk", "_unsigned.apk");
    }
	
	@Override
    protected void onPreExecute() {
        super.onPreExecute();
        pd = new ProgressDialog(mContext);
        pd.setTitle("Kill Signature Varification...");
        pd.setMessage("Processing...");
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
		signatures = getApkSignature(srcApk);
		
        publishProgress("Reading APK...");
        ZipFile zipFile = new ZipFile(srcApk);
		
        publishProgress("Processing AndroidManifest.xml...");
        ZipEntry manifestEntry = zipFile.getEntry("AndroidManifest.xml");
        byte[] manifestData = parseManifest(zipFile.getInputStream(manifestEntry));

		publishProgress("Processing classes.dex...");
        DexBackedDexFile dex = DexBackedDexFile.fromInputStream(Opcodes.getDefault(), mContext.getAssets().open("hook/hook.dex"));
		byte[] processDex = processDex(dex);

		// count total dex
        Enumeration<ZipEntry> entries = zipFile.getEntries();
		ArrayList arrayList = new ArrayList();
        while (entries.hasMoreElements()) {
            ZipEntry ze = entries.nextElement();
            String name = ze.getName();
            if ((name.startsWith("classes") && name.endsWith("dex")) || name.startsWith("./")) {
				arrayList.add(name);
            }
        }
        
        ZipOutputStream zos = new ZipOutputStream(new File(outApk));
        publishProgress("Adding AndroidManifest.xml...");
        zos.putNextEntry("AndroidManifest.xml");
        zos.write(manifestData);
        zos.closeEntry();
		
        publishProgress("Adding classes.dex...");
        zos.putNextEntry("classes" + (arrayList.size() + 1) + ".dex");
        zos.write(processDex);
        zos.closeEntry();
		
		// Copy other files from apk
        Enumeration<ZipEntry> enumeration = zipFile.getEntries();
        while (enumeration.hasMoreElements()) {
            ZipEntry ze = enumeration.nextElement();
            if (ze.getName().equals("AndroidManifest.xml") || ze.getName().startsWith("META-INF/")) continue;
            publishProgress("Adding files: " + ze.getName());
            zos.copyZipEntry(ze, zipFile);
        }
		
        zipFile.close();
		zos.close();
    }

	private byte[] processDex(DexBackedDexFile dex) throws Exception {
        DexBuilder dexBuilder = new DexBuilder(Opcodes.getDefault());
		for (DexBackedClassDef classDef : dex.getClasses()) {
			if (classDef.getType().equals("Lbin/mt/signature/KillerApplication;")) {
                StringWriter stringWriter = new StringWriter();
                Baksmali.disassembleClass(stringWriter, classDef, new BaksmaliOptions());
                String src = stringWriter.toString();
				
				if (customApplication) {
                    if (customApplicationName.startsWith(".")) {
                        if (packageName == null) throw new NullPointerException("Package name is null.");
                        customApplicationName = packageName + customApplicationName;
                    }
                    customApplicationName = "L" + customApplicationName.replace('.', '/') + ";";
                    src = src.replace("Landroid/app/Application;", customApplicationName);
                }
				
				if (signatures == null) throw new NullPointerException("Signatures is null");
                src = src.replace("###SIGNATURE_BASE64###", signatures).replace("###PACKAGE_NAME###", packageName);
				Smali.assembleSmaliFile(src, dexBuilder, new SmaliOptions());
			} else {
                dexBuilder.internClassDef(classDef);
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
        list.add("bin.mt.signature.KillerApplication");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        axml.write(list, baos);
        return baos.toByteArray();
    }
	
	
	public String getApkSignature(String apkPath) {
	    try {
			PackageInfo apkInfo = null;
            String hexSignature = null;
            Signature reconstructedSignature = null;
			
            PackageManager packageManager = this.mContext.getPackageManager();
            apkInfo = packageManager.getPackageArchiveInfo(apkPath, PackageManager.GET_SIGNATURES);
        
            hexSignature = extractCertificateHex(apkPath);
            if (hexSignature == null && apkInfo != null && apkInfo.signatures != null && apkInfo.signatures.length > 0) {
				 hexSignature = new String(bytesToHex(apkInfo.signatures[0].toByteArray()));
            }
			
            if (hexSignature != null) {
                byte[] certBytes = new BigInteger(hexSignature, 16).toByteArray();
                Certificate certificate = CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certBytes));
                reconstructedSignature = new Signature(certificate.getEncoded());
                if (apkInfo != null) {
                    apkInfo.signatures = new Signature[] {reconstructedSignature};
                }
            }
			if (apkInfo != null && apkInfo.signatures != null && apkInfo.signatures.length > 0) {
            return Base64.encodeToString(apkInfo.signatures[0].toByteArray(), Base64.NO_WRAP);
        }

        return (reconstructedSignature != null) ? Base64.encodeToString(reconstructedSignature.toByteArray(), Base64.NO_WRAP) : "";
        } catch (Exception ignored) {
			return "error!";
		}
    }

    public String extractCertificateHex(String apkPath) {
        byte[] buffer = new byte[8192];
        Certificate[] apkCertificates = null;
        try (JarFile jarFile = new JarFile(apkPath)) {
            Enumeration<JarEntry> jarEntries = jarFile.entries();
            while (jarEntries.hasMoreElements()) {
                JarEntry entry = jarEntries.nextElement();
                if (!entry.isDirectory() && !entry.getName().startsWith("META-INF/")) {
                    Certificate[] loadedCertificates = loadCertificates(jarFile, entry, buffer);
                    if (apkCertificates == null) {
                        apkCertificates = loadedCertificates;
                    } else if (!Arrays.equals(apkCertificates, loadedCertificates)) {
                        return null;
                    }
                }
            }
            if (apkCertificates == null || apkCertificates.length == 0) {
                return null;
            }
            return new String(bytesToHex(apkCertificates[0].getEncoded()));
        } catch (Exception e) {
            return null;
        }
    }
	
	public char[] bytesToHex(byte[] byteArray) {
        int length = byteArray.length;
        char[] hexChars = new char[length * 2];
        for (int index = 0; index < length; index++) {
            byte currentByte = byteArray[index];
            int highNibble = (currentByte >> 4) & 0xF;
            hexChars[index * 2] = (char) (highNibble >= 10 ? 'a' + (highNibble - 10) : '0' + highNibble);
            int lowNibble = currentByte & 0xF;
            hexChars[(index * 2) + 1] = (char) (lowNibble >= 10 ? 'a' + (lowNibble - 10) : '0' + lowNibble);
        }
        return hexChars;
    }
	
	private Certificate[] loadCertificates(JarFile jarFile, JarEntry jarEntry, byte[] buffer) {
        if (jarEntry == null) {
            return null;
        }
        try (InputStream inputStream = jarFile.getInputStream(jarEntry)) {
            while (inputStream.read(buffer, 0, buffer.length) != -1) {
                // Read until the end of the stream
            }
            return jarEntry.getCertificates();
        } catch (Exception e) {
            return null;
        }
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

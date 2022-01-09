package com.example.jetpackcryptoplayground;

import static androidx.security.crypto.MasterKey.DEFAULT_AES_GCM_MASTER_KEY_SIZE;
import static androidx.security.crypto.MasterKey.DEFAULT_MASTER_KEY_ALIAS;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.biometrics.BiometricPrompt.Builder;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.view.View;
import android.widget.Button;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import androidx.fragment.app.FragmentActivity;
import androidx.security.crypto.EncryptedFile;
import androidx.security.crypto.MasterKey;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.concurrent.Executor;

public class MainActivity extends AppCompatActivity {

    Context context;
    String masterKeyAlias;
    MasterKey masterKey;
    String encryptedFileName = "encrypted_data3.txt";

    // if masterKey is only allowed after biometric authorization
    private boolean _userAuth = true;
    private Executor executor;
    //private BiometricPrompt biometricPrompt;
    //private BiometricPrompt.PromptInfo promptInfo;

    Button generateMasterkey, writeFile, readFile, exportKeyset;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        context = getApplicationContext();

        generateMasterkey = (Button) findViewById(R.id.btnGenerateMasterKey);
        writeFile = (Button) findViewById(R.id.btnWriteFile);
        readFile = (Button) findViewById(R.id.btnReadFile);
        exportKeyset = (Button) findViewById(R.id.btnExportKeyset);

        generateMasterkey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                // Although you can define your own key generation parameter specification, it's
                // recommended that you use the value specified here.
                try {
                    // this is equivalent to using deprecated MasterKeys.AES256_GCM_SPEC

                    // short one
                    masterKey = getOrCreateMasterKey(getApplication());

                    /* long one
                    KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                            DEFAULT_MASTER_KEY_ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setKeySize(DEFAULT_AES_GCM_MASTER_KEY_SIZE)
                            .build();
                    masterKey = new MasterKey.Builder(MainActivity.this)
                            .setKeyGenParameterSpec(spec)
                            .setUserAuthenticationRequired(true) // true needs a biometric release
                            .setRequestStrongBoxBacked(false) // true needs a device with TEE
                            .build();
                    */

                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }
                System.out.println("new MasterKey generated:\n:" + masterKey.toString());
            }
        });

        /* old
        generateMasterkey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                // Although you can define your own key generation parameter specification, it's
                // recommended that you use the value specified here.
                KeyGenParameterSpec keyGenParameterSpec = AES256_GCM_SPEC;
                try {
                    mainKeyAlias = getOrCreate(keyGenParameterSpec);
                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }
                System.out.println("new MasterKey alias generated:\n:" + mainKeyAlias);
            }
        });
         */


        writeFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create a file with this name, or replace an entire existing file
                // that has the same name. Note that you cannot append to an existing file,
                // and the file name cannot contain path separators.
                File file = new File(context.getFilesDir(), encryptedFileName);
                if (file.exists()) {
                    System.out.println("file is existing, deleted");
                    file.delete();
                }
                EncryptedFile encryptedFile = null;
                try {
                    // check for biometric authorization
                    if (_userAuth) {
                        showBiometricPrompt(MainActivity.this);
                    } else {
                        // do nothing
                    }

                    encryptedFile = new EncryptedFile.Builder(
                            context,
                            file,
                            masterKey,
                            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB)
                            .build();
/*
                    encryptedFile = new EncryptedFile.Builder(
                            file,
                            context,
                            mainKeyAlias,
                            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                    ).build();*/
                    // https://stackoverflow.com/a/20648756/8166854
                    /*
"yyyy.MM.dd G 'at' HH:mm:ss z" ---- 2001.07.04 AD at 12:08:56 PDT
"hh 'o''clock' a, zzzz" ----------- 12 o'clock PM, Pacific Daylight Time
"EEE, d MMM yyyy HH:mm:ss Z"------- Wed, 4 Jul 2001 12:08:56 -0700
"yyyy-MM-dd'T'HH:mm:ss.SSSZ"------- 2001-07-04T12:08:56.235-0700
"yyMMddHHmmssZ"-------------------- 010704120856-0700
"K:mm a, z" ----------------------- 0:08 PM, PDT
"h:mm a" -------------------------- 12:08 PM
"EEE, MMM d, ''yy" ---------------- Wed, Jul 4, '01
                     */
                    DateFormat df = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss");
                    String date = df.format(Calendar.getInstance().getTime());
                    byte[] fileContent = ("MY SUPER-SECRET INFORMATION " + date)
                            .getBytes(StandardCharsets.UTF_8);
                    OutputStream outputStream = encryptedFile.openFileOutput();
                    outputStream.write(fileContent);
                    outputStream.flush();
                    outputStream.close();
                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }
                System.out.println("encrypted data written to: " + encryptedFileName);
            }
        });

        /* old
        writeFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Create a file with this name, or replace an entire existing file
                // that has the same name. Note that you cannot append to an existing file,
                // and the file name cannot contain path separators.
                File file = new File(context.getFilesDir(), encryptedFileName);
                if (file.exists()) {
                    System.out.println("file is existing, deleted");
                    file.delete();
                }
                EncryptedFile encryptedFile = null;
                try {
                    encryptedFile = new EncryptedFile.Builder(
                            file,
                            context,
                            mainKeyAlias,
                            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                    ).build();
                    byte[] fileContent = "MY SUPER-SECRET INFORMATION2"
                            .getBytes(StandardCharsets.UTF_8);
                    OutputStream outputStream = encryptedFile.openFileOutput();
                    outputStream.write(fileContent);
                    outputStream.flush();
                    outputStream.close();
                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }
                System.out.println("encrypted data written to: " + encryptedFileName);
            }
        });
         */


        readFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                File file = new File(context.getFilesDir(), encryptedFileName);
                EncryptedFile encryptedFile = null;
                byte[] plaintext;
                try {
                    // check for biometric authorization
                    if (_userAuth) {
                        showBiometricPrompt(MainActivity.this);
                        
                    } else {
                        // do nothing
                    }
                    encryptedFile = new EncryptedFile.Builder(
                            context,
                            file,
                            masterKey,
                            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                    ).build();
                    InputStream inputStream = encryptedFile.openFileInput();
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    int nextByte = inputStream.read();
                    while (nextByte != -1) {
                        byteArrayOutputStream.write(nextByte);
                        nextByte = inputStream.read();
                    }
                    plaintext = byteArrayOutputStream.toByteArray();
                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }
                System.out.println("decrypted file content:\n" +
                        new String(plaintext));
            }
        });

        /* old
        readFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                EncryptedFile encryptedFile = null;
                byte[] plaintext;
                try {
                    encryptedFile = new EncryptedFile.Builder(
                            new File(context.getFilesDir(), encryptedFileName),
                            context,
                            mainKeyAlias,
                            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB
                    ).build();
                    InputStream inputStream = encryptedFile.openFileInput();
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                    int nextByte = inputStream.read();
                    while (nextByte != -1) {
                        byteArrayOutputStream.write(nextByte);
                        nextByte = inputStream.read();
                    }
                    plaintext = byteArrayOutputStream.toByteArray();
                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }
                System.out.println("decrypted file content:\n" +
                        new String(plaintext));
            }
        });
         */

        exportKeyset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // https://stackoverflow.com/questions/64502478/export-keyset-entry-from-tink-with-androidkeysetmanager

                /*
                KeyGenParameterSpec keyGenParameterSpec = AES256_GCM_SPEC;
                try {
                    mainKeyAlias = getOrCreate(keyGenParameterSpec);
                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }
*/
                try {
                    MasterKey mk = getOrCreateMasterKey(getApplication());
                    System.out.println("mk: \n" + mk.toString());
                } catch (IOException | GeneralSecurityException e) {
                    e.printStackTrace();
                    System.out.println("error: " + e.toString());
                    return;
                }

                /*
                AndroidKeysetManager backupKeySetManager = new AndroidKeysetManager.Builder()
                        .withSharedPref(context, keysetName, "my_pref_file_name")
                        .withKeyTemplate(AesGcmHkdfStreamingKeyManager.aes256GcmHkdf4KBTemplate())
                        .withMasterKeyUri(MASTER_KEY_URI)
                        .build();
                String password = "password";
                try {
                    ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

                    final byte[] saltBytes = new byte[16];
                    new SecureRandom().nextBytes(saltBytes);

                    final byte[] encryptionKeyMaterial;

                    encryptionKeyMaterial = SecretKeyFactory.getInstance("PBKDF2withHmacSHA512")
                            .generateSecret(new PBEKeySpec(password.toCharArray(), saltBytes, 3000000, 256)).getEncoded();
                    final AesGcmJce aesGcmJce = new AesGcmJce(encryptionKeyMaterial);

                    CleartextKeysetHandle.write(backupKeySetManager.getKeysetHandle(),
                            BinaryKeysetWriter.withOutputStream(byteArrayOutputStream));

                    final byte[] clearKeyset = byteArrayOutputStream.toByteArray();

                    byteArrayOutputStream.reset();
                    byteArrayOutputStream.write(aesGcmJce.encrypt(clearKeyset, saltBytes));
                    byteArrayOutputStream.write(saltBytes);

                    byte[] output = byteArrayOutputStream.toByteArray();

                } catch (GeneralSecurityException | IOException e) {
                    e.printStackTrace();
                }

*/
            }
        });
    }

    public static void showBiometricPrompt(Activity activity) {

        androidx.biometric.BiometricPrompt prompt = new androidx.biometric.BiometricPrompt((FragmentActivity) activity, new androidx.biometric.BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(@NonNull androidx.biometric.BiometricPrompt.AuthenticationResult result) {

            }

            @Override
            public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                //Log.e(getClass().getSimpleName(), " authentication failed " + errorCode + " " + errString);
            }
        });
        //int authenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL | BiometricManager.Authenticators.BIOMETRIC_WEAK;

        //BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder().setTitle(activity.g etString(R.string.biometricAuthentificationRequired)).setAllowedAuthenticators(authenticators).build();
        //BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder().setTitle("biometric Authentification Required").setAllowedAuthenticators(authenticators).build();
        //androidx.biometric.BiometricPrompt.PromptInfo promptInfo = new androidx.biometric.BiometricPrompt.PromptInfo.Builder().setTitle("Zugang zur App nur mit\nFingerprint oder Geräte PIN").setAllowedAuthenticators(authenticators).build();

        // need to check allowed authenticators depending on sdk
        int authenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        // api 30+
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            authenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL | BiometricManager.Authenticators.BIOMETRIC_STRONG;
        }
        // api 23-29
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            authenticators = BiometricManager.Authenticators.DEVICE_CREDENTIAL;
        }

        // api 23+
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            androidx.biometric.BiometricPrompt.PromptInfo promptInfo = new androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Zugang zur App nur mit\nFingerprint oder Geräte PIN")
                    .setAllowedAuthenticators(authenticators)
                    //.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    //.setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL | BiometricManager.Authenticators.BIOMETRIC_STRONG)
                    .build();
            prompt.authenticate(promptInfo);
        }
        // api 21-22 does not support setAllowedAuthenticators
        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP &&
                android.os.Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {

                androidx.biometric.BiometricPrompt.PromptInfo promptInfo = new androidx.biometric.BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Zugang zur App nur mit\nFingerprint oder Geräte PIN")
                        .setDeviceCredentialAllowed(true)
                        //.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        //.setAllowedAuthenticators(BiometricManager.Authenticators.DEVICE_CREDENTIAL | BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .build();
                prompt.authenticate(promptInfo);
        }

    }


    private static MasterKey getOrCreateMasterKey(final Application application)
            throws IOException, GeneralSecurityException {
        return new MasterKey.Builder(application)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setUserAuthenticationRequired(true)
                //.setUserAuthenticationRequired(true, 3600)
                .setRequestStrongBoxBacked(true)
                .build();
    }
}

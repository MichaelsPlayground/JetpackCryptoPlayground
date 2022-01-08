package com.example.jetpackcryptoplayground;

import static androidx.security.crypto.MasterKeys.*;

import androidx.appcompat.app.AppCompatActivity;
import androidx.security.crypto.EncryptedFile;
import androidx.security.crypto.MasterKey;
import androidx.security.crypto.MasterKeys;

import android.app.Application;
import android.content.Context;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.view.View;
import android.widget.Button;

import com.google.crypto.tink.BinaryKeysetWriter;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.integration.android.AndroidKeysetManager;
import com.google.crypto.tink.streamingaead.AesGcmHkdfStreamingKeyManager;
import com.google.crypto.tink.subtle.AesGcmJce;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class MainActivity extends AppCompatActivity {

    Context context;
    String mainKeyAlias;
    String encryptedFileName = "encrypted_data.txt";

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

        readFile = (Button) findViewById(R.id.btnReadFile);
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

    private static MasterKey getOrCreateMasterKey(final Application application)
            throws IOException, GeneralSecurityException {
        return new MasterKey.Builder(application)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setUserAuthenticationRequired(true, 3600)
                .setRequestStrongBoxBacked(true)
                .build();
    }
}
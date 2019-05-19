/*
* Copyright 2013 The Android Open Source Project
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/


package com.example.android.cardemulation;

import android.app.KeyguardManager;
import android.content.SharedPreferences;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.v4.app.FragmentTransaction;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.Toast;
import android.widget.ViewAnimator;

import com.example.android.common.activities.SampleActivityBase;
import com.example.android.common.logger.Log;
import com.example.android.common.logger.LogFragment;
import com.example.android.common.logger.LogWrapper;
import com.example.android.common.logger.MessageOnlyLogFilter;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * A simple launcher activity containing a summary sample description, sample log and a custom
 * {@link android.support.v4.app.Fragment} which can display a view.
 * <p>
 * For devices with displays with a width of 720dp or greater, the sample log is always visible,
 * on other devices it's visibility is controlled by an item on the Action Bar.
 */
public class MainActivity extends SampleActivityBase {

    public static final String TAG = "MainActivity";

    private static final String DIALOG_FRAGMENT_TAG = "myFragment";
    private static final String SECRET_MESSAGE = "Very secret message";
    private static final String KEY_NAME_NOT_INVALIDATED = "key_not_invalidated";
    static final String DEFAULT_KEY_NAME = "default_key";

    private KeyStore mKeyStore;
    private KeyGenerator mKeyGenerator;
    private SharedPreferences mSharedPreferences;

    // Whether the Log Fragment is currently shown
    private boolean mLogShown;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        if (savedInstanceState == null) {
            FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
            CardEmulationFragment fragment = new CardEmulationFragment();
            transaction.replace(R.id.sample_content_fragment, fragment);
            transaction.commit();
        }

        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            throw new RuntimeException("Failed to get an instance of KeyStore", e);
        }
        try {
            mKeyGenerator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
        }
        Cipher defaultCipher;
        Cipher cipherNotInvalidated;
        try {
            defaultCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            cipherNotInvalidated = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                    + KeyProperties.BLOCK_MODE_CBC + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get an instance of Cipher", e);
        }
        mSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this);

        KeyguardManager keyguardManager = getSystemService(KeyguardManager.class);
        FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);

        if (!fingerprintManager.hasEnrolledFingerprints()) {
//            purchaseButton.setEnabled(false);
            // This happens when no fingerprints are registered.
            Toast.makeText(this,
                    "Go to 'Settings -> Security -> Fingerprint' and register at least one" +
                            " fingerprint",
                    Toast.LENGTH_LONG).show();
            return;
        }
        createKey(DEFAULT_KEY_NAME, true);
        createKey(KEY_NAME_NOT_INVALIDATED, false);

        if (initCipher(defaultCipher, DEFAULT_KEY_NAME)) {

            // Show the fingerprint dialog. The user has the option to use the fingerprint with
            // crypto, or you can fall back to using a server-side verified password.
            FingerprintAuthenticationDialogFragment fragment
                    = new FingerprintAuthenticationDialogFragment();

            fragment.setCryptoObject(new FingerprintManager.CryptoObject(defaultCipher));
            boolean useFingerprintPreference = mSharedPreferences
                    .getBoolean(getString(R.string.use_fingerprint_to_authenticate_key),
                            true);
            if (useFingerprintPreference) {
                fragment.setStage(
                        FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);
            } else {
                fragment.setStage(
                        FingerprintAuthenticationDialogFragment.Stage.PASSWORD);
            }
            fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
        } else {
            // This happens if the lock screen has been disabled or or a fingerprint got
            // enrolled. Thus show the dialog to authenticate with their password first
            // and ask the user if they want to authenticate with fingerprints in the
            // future
            FingerprintAuthenticationDialogFragment fragment
                    = new FingerprintAuthenticationDialogFragment();
            fragment.setCryptoObject(new FingerprintManager.CryptoObject(defaultCipher));
            fragment.setStage(
                    FingerprintAuthenticationDialogFragment.Stage.NEW_FINGERPRINT_ENROLLED);
            fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
        }


    }

    private boolean initCipher(Cipher cipher, String keyName) {
        try {
            mKeyStore.load(null);
            SecretKey key = (SecretKey) mKeyStore.getKey(keyName, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return true;
        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException
                | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }
    }

    public void createKey(String keyName, boolean invalidatedByBiometricEnrollment) {
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore.load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyName,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    // Require the user to authenticate with a fingerprint to authorize every use
                    // of the key
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);

            // This is a workaround to avoid crashes on devices whose API level is < 24
            // because KeyGenParameterSpec.Builder#setInvalidatedByBiometricEnrollment is only
            // visible on API level +24.
            // Ideally there should be a compat library for KeyGenParameterSpec.Builder but
            // which isn't available yet.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                builder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment);
            }
            mKeyGenerator.init(builder.build());
            mKeyGenerator.generateKey();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | CertificateException | IOException e) {
            throw new RuntimeException(e);
        }


    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        MenuItem logToggle = menu.findItem(R.id.menu_toggle_log);
        logToggle.setVisible(findViewById(R.id.sample_output) instanceof ViewAnimator);
        logToggle.setTitle(mLogShown ? R.string.sample_hide_log : R.string.sample_show_log);

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch(item.getItemId()) {
            case R.id.menu_toggle_log:
                mLogShown = !mLogShown;
                ViewAnimator output = (ViewAnimator) findViewById(R.id.sample_output);
                if (mLogShown) {
                    output.setDisplayedChild(1);
                } else {
                    output.setDisplayedChild(0);
                }
                supportInvalidateOptionsMenu();
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    /** Create a chain of targets that will receive log data */
    @Override
    public void initializeLogging() {
        // Wraps Android's native log framework.
        LogWrapper logWrapper = new LogWrapper();
        // Using Log, front-end to the logging chain, emulates android.util.log method signatures.
        Log.setLogNode(logWrapper);

        // Filter strips out everything except the message text.
        MessageOnlyLogFilter msgFilter = new MessageOnlyLogFilter();
        logWrapper.setNext(msgFilter);

        // On screen logging via a fragment with a TextView.
        LogFragment logFragment = (LogFragment) getSupportFragmentManager()
                .findFragmentById(R.id.log_fragment);
        msgFilter.setNext(logFragment.getLogView());

        Log.i(TAG, "Ready");
    }
}

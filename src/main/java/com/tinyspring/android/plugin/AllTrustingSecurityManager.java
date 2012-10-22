package com.tinyspring.android.plugin;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.h2.tinyspring.android.Application;
import com.h2.tinyspring.android.plugin.APlugin;

/**
 * This class installs all trusting security manager for TLS (https)
 * connections.
 * 
 * If a web site uses self-generate certificate or an authority which are not
 * included in standard java trust stores you would normally need to download
 * such certificate and manually install it into your java key chan.
 * 
 * This class will set custom all trusting security manager into SSL context so
 * all kind of certificates are accepted and trusted. Please keep in mind that
 * this is not very secure workaround and use it only at your own risk.
 * 
 * @author tomas.adamek
 * 
 */
public class AllTrustingSecurityManager extends APlugin {

    private static final Logger log = LoggerFactory.getLogger(AllTrustingSecurityManager.class);

    @Override
    public void onApplicationCreate(Application application) {
        super.onApplicationCreate(application);

        this.installAllTrustingSecurityManager();
    }

    private void installAllTrustingSecurityManager() {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                return new java.security.cert.X509Certificate[] {};
            }

            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }
        } };

        // Install the all-trusting trust manager
        try {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (Exception e) {
            log.error("Problem when installing an All Trusting Security Manager plugin for Tinyspring", e);
        }
    }
}

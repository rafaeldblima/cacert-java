package br.com.pemaza;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Main {

    private static final String JSSECACERTS = "/home/sys4/Documentos/reinf/Cacert";
    private static final int TIMEOUT_WS = 30;

    public static void main(String[] args) {
        try {
            char[] passphrase = "changeit".toCharArray();

            File file = new File(JSSECACERTS);
            System.out.println(file.getPath());
            if (!file.isFile()) {
                char SEP = File.separatorChar;
                File dir = new File(System.getProperty("java.home") + SEP + "lib" + SEP + "security");
                System.out.println(dir.getPath());
                file = new File(dir, JSSECACERTS);
                if (!file.isFile()) {
                    file = new File(dir, "cacerts");
                }
            }

            info("| Loading KeyStore " + file + "...");
            InputStream in = new FileInputStream(file);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(in, passphrase);
            in.close();

            get("homnfe.sefaz.am.gov.br", 443, ks);
            get("hnfe.sefaz.ba.gov.br", 443, ks);
            get("nfeh.sefaz.ce.gov.br", 443, ks);
            get("app.sefaz.es.gov.br", 443, ks);
            get("homolog.sefaz.go.gov.br", 443, ks);
            get("hnfe.fazenda.mg.gov.br", 443, ks);
            get("homologacao.nfe.ms.gov.br", 443, ks);
            get("homologacao.sefaz.mt.gov.br", 443, ks);
            get("nfehomolog.sefaz.pe.gov.br", 443, ks);
            get("homologacao.nfe.fazenda.pr.gov.br", 443, ks);
            get("nfe-homologacao.sefazrs.rs.gov.br", 443, ks);
            get("cad.sefazrs.rs.gov.br", 443, ks);
            get("homologacao.nfe.fazenda.sp.gov.br", 443, ks);
            get("hom.sefazvirtual.fazenda.gov.br", 443, ks);
            get("nfe-homologacao.svrs.rs.gov.br", 443, ks);
            get("cad.svrs.rs.gov.br", 443, ks);
            get("hom.svc.fazenda.gov.br", 443, ks);
            get("hom.nfe.fazenda.gov.br", 443, ks);
            get("nfe.sefaz.am.gov.br", 443, ks);
            get("nfe.sefaz.ba.gov.br", 443, ks);
            get("nfe.sefaz.ce.gov.br", 443, ks);
            get("nfe.sefaz.go.gov.br", 443, ks);
            get("nfe.fazenda.mg.gov.br", 443, ks);
            get("nfe.fazenda.ms.gov.br", 443, ks);
            get("nfe.sefaz.mt.gov.br", 443, ks);
            get("nfe.sefaz.pe.gov.br", 443, ks);
            get("nfe.fazenda.pr.gov.br", 443, ks);
            get("nfe.sefazrs.rs.gov.br", 443, ks);
            get("nfe.fazenda.sp.gov.br", 443, ks);
            get("www.sefazvirtual.fazenda.gov.br", 443, ks);
            get("nfe.svrs.rs.gov.br", 443, ks);
            get("www.svc.fazenda.gov.br", 443, ks);
            get("www.nfe.fazenda.gov.br", 443, ks);
            get("homnfce.sefaz.am.gov.br", 443, ks);
            get("nfceh.sefaz.ce.gov.br", 443, ks);
            get("homologacao.nfce.fazenda.ms.gov.br", 443, ks);
            get("nfcehomolog.sefaz.pe.gov.br", 443, ks);
            get("homologacao.nfce.fazenda.pr.gov.br", 443, ks);
            get("nfce-homologacao.sefazrs.rs.gov.br", 443, ks);
            get("homologacao.nfce.fazenda.sp.gov.br", 443, ks);
            get("nfce-homologacao.svrs.rs.gov.br", 443, ks);
            get("nfce.sefaz.am.gov.br", 443, ks);
            get("nfce.fazenda.ms.gov.br", 443, ks);
            get("nfce.sefaz.pe.gov.br", 443, ks);
            get("nfce.fazenda.pr.gov.br", 443, ks);
            get("nfce.sefazrs.rs.gov.br", 443, ks);
            get("nfce.fazenda.sp.gov.br", 443, ks);
            get("nfce.svrs.rs.gov.br", 443, ks);
            get("hcte.fazenda.mg.gov.br", 443, ks);
            get("homologacao.cte.ms.gov.br", 443, ks);
            get("homologacao.cte.fazenda.pr.gov.br", 443, ks);
            get("cte-homologacao.svrs.rs.gov.br", 443, ks);
            get("hom1.cte.fazenda.gov.br", 443, ks);
            get("cte.fazenda.mg.gov.br", 443, ks);
            get("producao.cte.ms.gov.br", 443, ks);
            get("cte.sefaz.mt.gov.br", 443, ks);
            get("cte.fazenda.pr.gov.br", 443, ks);
            get("cte.svrs.rs.gov.br", 443, ks);
            get("www1.cte.fazenda.gov.br", 443, ks);
            get("mdfe-homologacao.svrs.rs.gov.br", 443, ks);
            get("mdfe.svrs.rs.gov.br", 443, ks);
            get("webservices.producaorestrita.esocial.gov.br", 443, ks);
            get("webservices.consulta.esocial.gov.br", 443, ks);
            get("webservices.envio.esocial.gov.br", 443, ks);
            get("preprodefdreinf.receita.fazenda.gov.br", 443, ks);

            File cafile = new File(JSSECACERTS);
            OutputStream out = new FileOutputStream(cafile);
            ks.store(out, passphrase);
            out.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void get(String host, int port, KeyStore ks) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        info("| Opening connection to " + host + ":" + port + "...");
        SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(TIMEOUT_WS * 1000);
        try {
            info("| Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            info("| No errors, certificate is already trusted");
        } catch (SSLHandshakeException e) {
            /**
             * PKIX path building failed:
             * sun.security.provider.certpath.SunCertPathBuilderException:
             * unable to find valid certification path to requested target
             * Não tratado, pois sempre ocorre essa exceção quando o cacerts
             * nao esta gerado.
             */
        } catch (SSLException e) {
            error("| " + e.toString());
        }

        X509Certificate[] chain = tm.chain;
        if (chain == null) {
            info("| Could not obtain server certificate chain");
        }

        info("| Server sent " + chain.length + " certificate(s):");
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            sha1.update(cert.getEncoded());
            md5.update(cert.getEncoded());

            String alias = host + "-" + (i);
            ks.setCertificateEntry(alias, cert);
            info("| Added certificate to keystore '" + JSSECACERTS + "' using alias '" + alias + "'");
        }
    }

    private static class SavingTrustManager implements X509TrustManager {
        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

    private static void info(String log) {
        System.out.println("INFO: " + log);
    }

    private static void error(String log) {
        System.out.println("ERROR: " + log);
    }
}

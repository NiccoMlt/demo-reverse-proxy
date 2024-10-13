package com.diennea.carapace;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

public class Main {

    public static void main(final String... args) throws KeyStoreException {
        final Provider[] providers = Security.getProviders();
        System.out.println("Providers: " + Arrays.toString(providers));

        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        System.out.println("KeyStore: " + keyStore.getType());
    }
}

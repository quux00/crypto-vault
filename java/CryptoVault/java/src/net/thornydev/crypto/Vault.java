package net.thornydev.crypto;

import java.io.InputStream;
import java.io.OutputStream;

public interface Vault {
  public void initializeVault();
  public OutputStream vaultOutputStream();    
  public InputStream vaultInputStream();
  public void encryptToVault(String msg);
  public String decryptFromVault();
  
  public String getPassword();
  public String getFilename();
  public String getKeystoreName();
}

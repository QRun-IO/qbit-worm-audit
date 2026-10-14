/*
 * QQQ - Low-code Application Framework for Engineers.
 * Copyright (C) 2021-2025.  Kingsrook, LLC
 * 651 N Broad St Ste 205 # 6917 | Middletown DE 19709 | United States
 * contact@kingsrook.com
 * https://github.com/Kingsrook/
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.kingsrook.qbits.wormaudit;


import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Map;
import java.util.function.Supplier;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.kingsrook.qqq.backend.core.model.metadata.producers.MetaDataCustomizerInterface;
import com.kingsrook.qqq.backend.core.model.metadata.qbits.QBitConfig;
import com.kingsrook.qqq.backend.core.model.metadata.tables.QTableMetaData;


/*******************************************************************************
 ** Host configuration. Private signing material never enters metadata records.
 *******************************************************************************/
public class WormAuditQBitConfig implements QBitConfig
{
   public static final int DEFAULT_RETENTION_YEARS = 6;

   /*******************************************************************************
    ** Signing identity; the matching public key must be pinned in trustedPublicKeys.
    *******************************************************************************/
   public record SigningKey(String keyId, PrivateKey privateKey)
   {
   }

   private String exportLockMode = "GOVERNANCE";
   private int exportRetentionDays = 30;
   private final WormAuditSettings settings = new WormAuditSettings(this);
   private String appName = "worm_audit";
   private String appLabel = "WORM Audit";
   private String parentAppName;
   private String tablePathPrefix = "/app";
   private Supplier<com.kingsrook.qbits.wormaudit.export.SealedStore> sealedStoreSupplier;
   private String backendName = null;
   private int retentionYears = 6;
   private Supplier<SigningKey> signingKey = null;
   private Map<String, PublicKey> trustedPublicKeys = Map.of();
   private int chainIntervalSeconds = 30;
   private int settleHorizonSeconds = 60;
   private int batchSize = 1000;
   private int lateDetailLookbackHours = 24;
   private int checkpointEveryLinks = 10000;
   private int checkpointEveryMinutes = 60;
   private String verifyCron = "0 0 3 * * ?";
   private String exportBucketAlias = "worm_audit";
   private String exportPrefix = "worm-audit";
   private String exportCron = "0 0 2 * * ?";
   private String schedulerName = "worm_audit";
   private Map<String, String> coreAuditTableNames = Map.of();
   private String appRole = "app";
   private MetaDataCustomizerInterface<QTableMetaData> tableMetaDataCustomizer = null;


   /*******************************************************************************
    ** Read exportLockMode.
    *******************************************************************************/
   public String getExportLockMode()
   {
      return (exportLockMode);
   }


   /*******************************************************************************
    ** Configure exportLockMode.
    *******************************************************************************/
   public WormAuditQBitConfig withExportLockMode(String exportLockMode)
   {
      this.exportLockMode = exportLockMode;
      return (this);
   }


   /*******************************************************************************
    ** Read exportRetentionDays.
    *******************************************************************************/
   public int getExportRetentionDays()
   {
      return (exportRetentionDays);
   }


   /*******************************************************************************
    ** Configure exportRetentionDays.
    *******************************************************************************/
   public WormAuditQBitConfig withExportRetentionDays(int exportRetentionDays)
   {
      this.exportRetentionDays = exportRetentionDays;
      return (this);
   }


   /*******************************************************************************
    ** Read effective settings through the instance-scoped 30-second cache.
    *******************************************************************************/
   @JsonIgnore
   public WormAuditSettings.Values effectiveSettings()
   {
      return (settings.read());
   }


   /*******************************************************************************
    ** Discard this instance's cached row after a successful local settings write.
    *******************************************************************************/
   public void invalidateSettings()
   {
      settings.invalidate();
   }


   /*******************************************************************************
    ** Read the app name.
    *******************************************************************************/
   public String getAppName()
   {
      return (appName);
   }


   /*******************************************************************************
    ** Configure the app name.
    *******************************************************************************/
   public WormAuditQBitConfig withAppName(String appName)
   {
      this.appName = appName;
      return (this);
   }


   /*******************************************************************************
    ** Read the app label.
    *******************************************************************************/
   public String getAppLabel()
   {
      return (appLabel);
   }


   /*******************************************************************************
    ** Configure the app label.
    *******************************************************************************/
   public WormAuditQBitConfig withAppLabel(String appLabel)
   {
      this.appLabel = appLabel;
      return (this);
   }


   /*******************************************************************************
    ** Read the optional parent app.
    *******************************************************************************/
   public String getParentAppName()
   {
      return (parentAppName);
   }


   /*******************************************************************************
    ** Configure the optional parent app.
    *******************************************************************************/
   public WormAuditQBitConfig withParentAppName(String parentAppName)
   {
      this.parentAppName = parentAppName;
      return (this);
   }


   /*******************************************************************************
    ** Read the table route prefix.
    *******************************************************************************/
   public String getTablePathPrefix()
   {
      return (tablePathPrefix);
   }


   /*******************************************************************************
    ** Configure the table route prefix.
    *******************************************************************************/
   public WormAuditQBitConfig withTablePathPrefix(String tablePathPrefix)
   {
      this.tablePathPrefix = tablePathPrefix;
      return (this);
   }


   /*******************************************************************************
    ** Read the optional storage boundary (defaults to qbit-object-storage).
    *******************************************************************************/
   @JsonIgnore
   public Supplier<com.kingsrook.qbits.wormaudit.export.SealedStore> getSealedStoreSupplier()
   {
      return (sealedStoreSupplier);
   }


   /*******************************************************************************
    ** Configure the optional storage boundary (defaults to qbit-object-storage).
    *******************************************************************************/
   public WormAuditQBitConfig withSealedStoreSupplier(Supplier<com.kingsrook.qbits.wormaudit.export.SealedStore> sealedStoreSupplier)
   {
      this.sealedStoreSupplier = sealedStoreSupplier;
      return (this);
   }


   /*******************************************************************************
    ** Read backendName.
    *******************************************************************************/
   public String getBackendName()
   {
      return (backendName);
   }


   /*******************************************************************************
    ** Configure backendName.
    *******************************************************************************/
   public WormAuditQBitConfig withBackendName(String backendName)
   {
      this.backendName = backendName;
      return (this);
   }


   /*******************************************************************************
    ** Read retentionYears.
    *******************************************************************************/
   public int getRetentionYears()
   {
      return (retentionYears);
   }


   /*******************************************************************************
    ** Configure retentionYears.
    *******************************************************************************/
   public WormAuditQBitConfig withRetentionYears(int retentionYears)
   {
      this.retentionYears = retentionYears;
      return (this);
   }


   /*******************************************************************************
    ** Read signingKey.
    *******************************************************************************/
   @JsonIgnore
   public Supplier<SigningKey> getSigningKey()
   {
      return (signingKey);
   }


   /*******************************************************************************
    ** Configure signingKey.
    *******************************************************************************/
   public WormAuditQBitConfig withSigningKey(Supplier<SigningKey> signingKey)
   {
      this.signingKey = signingKey;
      return (this);
   }


   /*******************************************************************************
    ** Read trustedPublicKeys.
    *******************************************************************************/
   @JsonIgnore
   public Map<String, PublicKey> getTrustedPublicKeys()
   {
      return (trustedPublicKeys);
   }


   /*******************************************************************************
    ** Configure trustedPublicKeys.
    *******************************************************************************/
   public WormAuditQBitConfig withTrustedPublicKeys(Map<String, PublicKey> trustedPublicKeys)
   {
      this.trustedPublicKeys = trustedPublicKeys;
      return (this);
   }


   /*******************************************************************************
    ** Read chainIntervalSeconds.
    *******************************************************************************/
   public int getChainIntervalSeconds()
   {
      return (chainIntervalSeconds);
   }


   /*******************************************************************************
    ** Configure chainIntervalSeconds.
    *******************************************************************************/
   public WormAuditQBitConfig withChainIntervalSeconds(int chainIntervalSeconds)
   {
      this.chainIntervalSeconds = chainIntervalSeconds;
      return (this);
   }


   /*******************************************************************************
    ** Read settleHorizonSeconds.
    *******************************************************************************/
   public int getSettleHorizonSeconds()
   {
      return (settleHorizonSeconds);
   }


   /*******************************************************************************
    ** Configure settleHorizonSeconds.
    *******************************************************************************/
   public WormAuditQBitConfig withSettleHorizonSeconds(int settleHorizonSeconds)
   {
      this.settleHorizonSeconds = settleHorizonSeconds;
      return (this);
   }


   /*******************************************************************************
    ** Read the bounded late-detail polling window in hours.
    *******************************************************************************/
   public int getLateDetailLookbackHours()
   {
      return (lateDetailLookbackHours);
   }


   /*******************************************************************************
    ** Configure late-detail polling; older omissions are reported by verification.
    *******************************************************************************/
   public WormAuditQBitConfig withLateDetailLookbackHours(int lateDetailLookbackHours)
   {
      this.lateDetailLookbackHours = lateDetailLookbackHours;
      return (this);
   }


   /*******************************************************************************
    ** Read batchSize.
    *******************************************************************************/
   public int getBatchSize()
   {
      return (batchSize);
   }


   /*******************************************************************************
    ** Configure batchSize.
    *******************************************************************************/
   public WormAuditQBitConfig withBatchSize(int batchSize)
   {
      this.batchSize = batchSize;
      return (this);
   }


   /*******************************************************************************
    ** Read checkpointEveryLinks.
    *******************************************************************************/
   public int getCheckpointEveryLinks()
   {
      return (checkpointEveryLinks);
   }


   /*******************************************************************************
    ** Configure checkpointEveryLinks.
    *******************************************************************************/
   public WormAuditQBitConfig withCheckpointEveryLinks(int checkpointEveryLinks)
   {
      this.checkpointEveryLinks = checkpointEveryLinks;
      return (this);
   }


   /*******************************************************************************
    ** Read checkpointEveryMinutes.
    *******************************************************************************/
   public int getCheckpointEveryMinutes()
   {
      return (checkpointEveryMinutes);
   }


   /*******************************************************************************
    ** Configure checkpointEveryMinutes.
    *******************************************************************************/
   public WormAuditQBitConfig withCheckpointEveryMinutes(int checkpointEveryMinutes)
   {
      this.checkpointEveryMinutes = checkpointEveryMinutes;
      return (this);
   }


   /*******************************************************************************
    ** Read verifyCron.
    *******************************************************************************/
   public String getVerifyCron()
   {
      return (verifyCron);
   }


   /*******************************************************************************
    ** Read the Object Lock bucket alias.
    *******************************************************************************/
   public String getExportBucketAlias()
   {
      return (exportBucketAlias);
   }


   /*******************************************************************************
    ** Configure the Object Lock bucket alias.
    *******************************************************************************/
   public WormAuditQBitConfig withExportBucketAlias(String exportBucketAlias)
   {
      this.exportBucketAlias = exportBucketAlias;
      return (this);
   }


   /*******************************************************************************
    ** Read the export key prefix.
    *******************************************************************************/
   public String getExportPrefix()
   {
      return (exportPrefix);
   }


   /*******************************************************************************
    ** Configure the export key prefix.
    *******************************************************************************/
   public WormAuditQBitConfig withExportPrefix(String exportPrefix)
   {
      this.exportPrefix = exportPrefix;
      return (this);
   }


   /*******************************************************************************
    ** Read the UTC export schedule.
    *******************************************************************************/
   public String getExportCron()
   {
      return (exportCron);
   }


   /*******************************************************************************
    ** Configure the UTC export schedule.
    *******************************************************************************/
   public WormAuditQBitConfig withExportCron(String exportCron)
   {
      this.exportCron = exportCron;
      return (this);
   }


   /*******************************************************************************
    ** Configure verifyCron.
    *******************************************************************************/
   public WormAuditQBitConfig withVerifyCron(String verifyCron)
   {
      this.verifyCron = verifyCron;
      return (this);
   }


   /*******************************************************************************
    ** Read schedulerName.
    *******************************************************************************/
   public String getSchedulerName()
   {
      return (schedulerName);
   }


   /*******************************************************************************
    ** Configure schedulerName.
    *******************************************************************************/
   public WormAuditQBitConfig withSchedulerName(String schedulerName)
   {
      this.schedulerName = schedulerName;
      return (this);
   }


   /*******************************************************************************
    ** Read coreAuditTableNames.
    *******************************************************************************/
   public Map<String, String> getCoreAuditTableNames()
   {
      return (coreAuditTableNames);
   }


   /*******************************************************************************
    ** Configure coreAuditTableNames.
    *******************************************************************************/
   public WormAuditQBitConfig withCoreAuditTableNames(Map<String, String> coreAuditTableNames)
   {
      this.coreAuditTableNames = coreAuditTableNames;
      return (this);
   }


   /*******************************************************************************
    ** Read appRole.
    *******************************************************************************/
   public String getAppRole()
   {
      return (appRole);
   }


   /*******************************************************************************
    ** Configure appRole.
    *******************************************************************************/
   public WormAuditQBitConfig withAppRole(String appRole)
   {
      this.appRole = appRole;
      return (this);
   }


   /*******************************************************************************
    ** Read tableMetaDataCustomizer.
    *******************************************************************************/
   @Override
   public MetaDataCustomizerInterface<QTableMetaData> getTableMetaDataCustomizer()
   {
      return (tableMetaDataCustomizer);
   }


   /*******************************************************************************
    ** Configure tableMetaDataCustomizer.
    *******************************************************************************/
   public WormAuditQBitConfig withTableMetaDataCustomizer(MetaDataCustomizerInterface<QTableMetaData> tableMetaDataCustomizer)
   {
      this.tableMetaDataCustomizer = tableMetaDataCustomizer;
      return (this);
   }


   /*******************************************************************************
    ** Reject invalid runtime limits before producing metadata.
    *******************************************************************************/
   public void validate()
   {
      if(appName == null || !appName.matches("[A-Za-z0-9_-]+") || appLabel == null || appLabel.isBlank()
         || (parentAppName != null && !parentAppName.matches("[A-Za-z0-9_-]+"))
         || tablePathPrefix == null || !tablePathPrefix.matches("/[A-Za-z0-9_/-]*") || tablePathPrefix.endsWith("/"))
      {
         throw (new IllegalArgumentException("App names and a local table path prefix are required"));
      }
      if(exportBucketAlias == null || exportBucketAlias.isBlank() || exportCron == null || exportCron.isBlank()
         || exportPrefix == null || !exportPrefix.matches("[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*"))
      {
         throw (new IllegalArgumentException("Export bucket, prefix and schedule must be configured"));
      }
      WormAuditSettings.validate(WormAuditSettings.defaults(this));
      if(backendName == null || backendName.isBlank() || retentionYears < 1 || chainIntervalSeconds < 1
         || lateDetailLookbackHours < 1 || settleHorizonSeconds < 0 || batchSize < 1 || checkpointEveryLinks < 1 || checkpointEveryMinutes < 1)
      {
         throw (new IllegalArgumentException("backendName is required and WORM audit limits must be positive (settle horizon may be zero)"));
      }
   }
}

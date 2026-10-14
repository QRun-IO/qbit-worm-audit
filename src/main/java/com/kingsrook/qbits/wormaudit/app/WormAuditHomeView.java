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

package com.kingsrook.qbits.wormaudit.app;


import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import com.kingsrook.qbits.wormaudit.model.WormAuditTables;
import com.kingsrook.qqq.backend.core.model.data.QRecord;


/*******************************************************************************
 ** Stacked, wrapping definition lists. Colors follow BackupsHomeView exactly:
 ** inherited text/link colors, translucent neutral borders, muted opacity. Only
 ** allowlisted summary fields are rendered; no audit content is ever inspected.
 *******************************************************************************/
public final class WormAuditHomeView
{
   private static final DateTimeFormatter WHEN = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC);
   private static final String CARD = "border:1px solid rgba(127,127,127,.3);border-radius:8px;padding:1rem;min-width:0;overflow-wrap:anywhere;";
   private static final String LINK = "color:inherit;text-decoration:underline;text-underline-offset:2px;";

   /*******************************************************************************
    ** Utility class.
    *******************************************************************************/
   private WormAuditHomeView()
   {
   }


   /*******************************************************************************
    ** Full home with explicit empty states and no fixed-width content.
    *******************************************************************************/
   public static String render(WormAuditHomeData data, String prefix)
   {
      StringBuilder html = new StringBuilder("<div class=\"worm-audit-home\" style=\"display:grid;gap:1rem;min-width:0;max-width:100%;\">");
      open(html, "Chain status");
      row(html, "Links chained", data.links());
      row(html, "Last link", when(data.lastLinkAt(), "No links chained yet"));
      row(html, "Unchained backlog", data.backlog() + " settled; " + data.settling() + " settling (" + data.settleSeconds() + " s horizon)");
      QRecord verification = data.lastVerification();
      if(verification == null)
      {
         row(html, "Last verification", "No verification has run yet");
      }
      else
      {
         linkedRow(html, "Last verification", recordLink(prefix, WormAuditTables.VERIFICATION, verification.getValueLong("id"), "Verification #" + verification.getValueLong("id")));
         row(html, "Verified at", when(verification.getValueInstant("finished_at"), "Not recorded"));
         row(html, "Result", verification.getValueString("outcome") + "; " + verification.getValueLong("links_checked") + " links checked");
      }
      QRecord broken = data.openBreak();
      if(broken == null)
      {
         row(html, "Open chain breaks", verification == null ? "Unknown until verification runs" : "None reported");
      }
      else
      {
         linkedRow(html, "Open chain breaks", recordLink(prefix, WormAuditTables.VERIFICATION, broken.getValueLong("id"), broken.getValueLong("break_count") + " reported"));
         linkedRow(html, "First break link", recordLink(prefix, WormAuditTables.CHAIN, broken.getValueLong("first_break_link_id"), "Link #" + broken.getValueLong("first_break_link_id")));
         row(html, "First break audit", broken.getValueLong("first_break_audit_id"));
         row(html, "Reason", broken.getValueString("first_break_reason"));
      }
      close(html);
      open(html, "Export status");
      row(html, "Export lock mode", data.exportLockMode());
      row(html, "Export retention", data.exportRetentionDays() + " days");
      QRecord export = data.lastExport();
      if(export == null)
      {
         row(html, "Last sealed export", "No sealed exports yet");
      }
      else
      {
         linkedRow(html, "Last sealed export", recordLink(prefix, WormAuditTables.EXPORT, export.getValueLong("id"), "Export #" + export.getValueLong("id")));
         row(html, "Link range", export.getValueLong("from_link_id") + "–" + export.getValueLong("to_link_id"));
         row(html, "Sealed at", when(export.getValueInstant("sealed_at"), "Not recorded"));
         row(html, "Retain until", when(export.getValueInstant("retain_until"), "Not recorded"));
         row(html, "Last export lock mode", export.getValueString("lock_mode"));
      }
      row(html, "Export lag", data.exportLag() + " links; " + (data.exportAgeHours() == null ? "no previous export time" : data.exportAgeHours() + " h since last export"));
      row(html, "Gaps in sealed ranges", data.exportGaps().isEmpty() ? (export == null ? "No sealed ranges to check" : "None") : String.join(", ", data.exportGaps()));
      row(html, "Bucket alias", data.bucketAlias());
      row(html, "Object Lock capability", data.lockCapability() + (data.lockReason() == null ? "" : ": " + data.lockReason()));
      close(html);
      open(html, "Retention");
      row(html, "Configured retention", data.retentionYears() + " years");
      QRecord anchor = data.anchor();
      row(html, "Purge anchor", anchor == null ? "None" : "Link #" + anchor.getValueLong("anchor_link_id") + "; hash " + shortHash(anchor.getValueString("anchor_hash")));
      row(html, "Oldest live audit", when(data.oldestAudit(), "No live audits"));
      row(html, "Next eligible purge", when(data.nextPurge(), "No live audits to purge"));
      close(html);
      open(html, "Recent purges");
      if(data.recentPurges().isEmpty())
      {
         row(html, "History", "No purge requests yet");
      }
      for(QRecord purge : data.recentPurges())
      {
         linkedRow(html, "Purge", recordLink(prefix, WormAuditTables.PURGE, purge.getValueLong("id"), "Purge #" + purge.getValueLong("id")));
         row(html, "Requested at", when(purge.getValueInstant("requested_at"), "Not recorded"));
         row(html, "Requested by", purge.getValueString("requested_by"));
         row(html, "Outcome", purge.getValueString("outcome"));
         row(html, "Cutoff", when(purge.getValueInstant("cutoff"), "Not recorded"));
         row(html, "Deleted", purge.getValueLong("audits_deleted") + " audits; " + purge.getValueLong("details_deleted") + " details; " + purge.getValueLong("links_deleted") + " links");
         row(html, "Reason", purge.getValueString("reason"));
      }
      close(html);
      if(!data.warnings().isEmpty())
      {
         open(html, "Setup warnings");
         for(String warning : data.warnings())
         {
            row(html, "Warning", warning);
         }
         close(html);
      }
      return (html.append("</div>").toString());
   }


   /*******************************************************************************
    ** Honest compact status, owned by and linked to the full home.
    *******************************************************************************/
   public static String renderHealthCard(WormAuditHomeData data, String homePath)
   {
      String status = data.openBreak() != null ? "Chain breaks reported" : data.lastVerification() == null ? "Not verified yet"
         : data.warnings().isEmpty() ? "No open chain breaks reported" : "Setup needs attention";
      return ("<div style=\"" + CARD + "\"><strong>" + esc(status) + "</strong><p>" + data.links() + " links; " + data.backlog()
         + " settled audits waiting; " + data.exportLag() + " links awaiting export.</p><a style=\"" + LINK + "\" href=\"" + esc(homePath) + "\">Open WORM Audit</a></div>");
   }


   /*******************************************************************************
    ** Section and definition list, with fluid wrapping label/value rows.
    *******************************************************************************/
   private static void open(StringBuilder html, String title)
   {
      html.append("<section style=\"").append(CARD).append("\"><h3 style=\"margin:0 0 .75rem;font-size:1rem;font-weight:600;\">")
         .append(esc(title)).append("</h3><dl style=\"margin:0;font-size:.9rem;\">");
   }


   /*******************************************************************************
    ** Close a section.
    *******************************************************************************/
   private static void close(StringBuilder html)
   {
      html.append("</dl></section>");
   }


   /*******************************************************************************
    ** Escape every value, including reasons and runtime identities.
    *******************************************************************************/
   private static void row(StringBuilder html, String label, Object value)
   {
      linkedRow(html, label, esc(value == null ? "Not recorded" : value.toString()));
   }


   /*******************************************************************************
    ** Only internally built and escaped links may supply HTML here.
    *******************************************************************************/
   private static void linkedRow(StringBuilder html, String label, String value)
   {
      html.append("<div style=\"display:flex;flex-wrap:wrap;gap:.25rem .75rem;margin:.4rem 0;min-width:0;\"><dt style=\"opacity:.75;flex:0 1 12rem;\">")
         .append(esc(label)).append("</dt><dd style=\"margin:0;flex:1 1 14rem;min-width:0;overflow-wrap:anywhere;\">").append(value).append("</dd></div>");
   }


   /*******************************************************************************
    ** Standard QQQ record route; identifiers are numeric, never content.
    *******************************************************************************/
   private static String recordLink(String prefix, String table, Long id, String text)
   {
      return (id == null ? "Not recorded" : "<a style=\"" + LINK + "\" href=\"" + esc(prefix + "/" + table + "/" + id) + "\">" + esc(text) + "</a>");
   }


   /*******************************************************************************
    ** UTC time with an explicit empty state.
    *******************************************************************************/
   private static String when(Instant time, String empty)
   {
      return (time == null ? empty : WHEN.format(time));
   }


   /*******************************************************************************
    ** Keep hashes compact even on a narrow screen.
    *******************************************************************************/
   private static String shortHash(String hash)
   {
      return (hash == null ? "Not recorded" : hash.substring(0, Math.min(12, hash.length())) + "…");
   }


   /*******************************************************************************
    ** HTML text and quoted attribute escaping.
    *******************************************************************************/
   private static String esc(String text)
   {
      return (text == null ? "" : text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;"));
   }
}

package com.bbs.vol.windows

object CreateReport {

  def run(memFile: String, os: String, process: ProcessBrain, disc: Discovery, riskRating: Int) = {
    /** Using StringBuilder for fast concatenation of Strings. */
    val report = new StringBuilder()

    /** Grab info we need for report. */
    // YaraParseString(rule, proc, str)
    // YaraParse(classification, rule, owner, offset)
    val proc: Vector[ProcessBbs] = disc.proc._1
    /** callbacks, hiddenModules, timers, deviceTree, orphanThread, found */
    val rootkit: RootkitResults = disc.rootkit
    /** (pid -> Remote Mapped Drive) */
    val remoteMapped: Vector[(String, String)] = disc.remoteMapped
    /** Vector[String], Vector[String] */
    val registry = disc.registry
    /** svcStopped, suspCmds */
    val sysSt: SysState = disc.sysState

    val net: Vector[NetConnections] = disc.net._1

    /**
      * Get info from ProcessBrain
      */
    val yaraObj: YaraBrain = process.yara
    val regPersist: Vector[RegPersistenceInfo] = process.regPersistence // done
    val ldr: Vector[LdrInfo] = process.ldrInfo // done
    val privs: Vector[Privileges] = process.privs // done

    val promiscModeMap: Map[String, Boolean] = process.promiscMode

    /** Write Report */
    val intro = s"Big Brain Security Volatile IDS Report for $memFile\n\nSummary:\n\n\tRisk Rating: $riskRating\n\n"
    report.append(intro + "\tMalware Found: \n\n")
    /** Yara malware findings */
    val malware: String = malwareFound(yaraObj)
    report.append(malware)
    report.append("Significant Findings:\n\n")

  } // END run()

  private[this] def malwareFound(yaraObj: YaraBrain): String = {

    val reportStr = new StringBuilder()
    /** Grab significant yara scan findings */
    val yarMalware: Vector[YaraParseString] = yaraObj.malware
    val yarSuspicious: YaraSuspicious = yaraObj.suspItems
    val antidebug: Vector[YaraParse] = yarSuspicious.antidebug
    val exploitKits: Vector[YaraParse] = yarSuspicious.exploitKits
    val webshells: Vector[YaraParse] = yarSuspicious.webshells
    val malDocs: Vector[YaraParse] = yarSuspicious.malDocs

    /** Malware results. */
    // var malStr = ""
    if(yarMalware.nonEmpty){
      val malwareConcat = yarMalware.map(x => x.rule).mkString("\n\t")
      reportStr.append(s"\tThe following malware signatures were found with yara: \n\t$malwareConcat\n\n")
    } // END if
    if(antidebug.nonEmpty){
      val antidebugConcat = yarMalware.map(x => x.rule).mkString("\n\t")
      reportStr.append(s"\tThe following antidebug signatures were found with yara: \n\t$antidebugConcat\n\n")
    }
    if(exploitKits.nonEmpty){
      val exploitConcat = yarMalware.map(x => x.rule).mkString("\n\t")
      reportStr.append(s"\tThe following exploit kit signatures were found with yara: \n\t$exploitConcat\n\n")
    } // END if
    if(webshells.nonEmpty){
      val shellConcat = yarMalware.map(x => x.rule).mkString("\n\t")
      reportStr.append(s"\tThe following web shell signatures were found with yara: \n\t$shellConcat\n\n")
    }
    if(malDocs.nonEmpty){
      val malConcat = yarMalware.map(x => x.rule).mkString("\n\t")
      reportStr.append(s"\tThe following malicious document signatures were found with yara: \n\t$malConcat\n\n")
    }

    if(reportStr.isEmpty) reportStr.append("\tNone\n\n")

    return reportStr.toString
  } // END malwareFound()
} // END CreateReport

package com.bbs.vol.utils

/**
  * Program cleans up files created in volatility directory after program finishes running.
  */

import java.nio.file.{Files, Paths}
import java.nio.file.StandardCopyOption._
import java.io.File

import com.bbs.vol.windows.ProcessBbsScan.writeToFile

class CleanUp(dest: String) extends FileFun {
  val destination: String = dest

  private[vol] def prepForMove = {
    val dumpsPath = dest + "/Dumps"

    val dumpDir = new File(dumpsPath)
    dumpDir.mkdir()

    val scansPath = dest + "/Full_Scans"
    val scansDir = new File(scansPath)
    scansDir.mkdir()
  } // END prepForMove()

  private[vol] def writeAndMoveDumps(outputFile: String, scan: String)  = {
    writeToFile(outputFile , scan)
    mvFileDump(outputFile)
  }

  private[vol] def writeAndMoveScans(outputFile: String, scan: String)  = {
    writeToFile(outputFile , scan)
    mvFileScans(outputFile)
  }

  /** Move a data structure of files to Dumps directory. */
  private[vol] def mvSeqToDumps(files: Seq[String]) = {

    for(file <- files) moveFile(file, dest + "/Dumps")

  }// END mvFiles()

  /** Move a data structure of file paths to Full_Scans. */
  private[vol] def mvSeqToScans(files: Seq[String]) = {

    for(file <- files) moveFile(file, dest + "/Full_Scans")

  } // END mvFiles()

  /** move a single file to Dumps directory */
  private[vol] def mvFileDump(file: String) = {
    moveFile(file, dest + "/Dumps")
  } // END mvFileDump()

  /** move a single file to Full_Scans directory */
  private[vol] def mvFileScans(file: String) = {
    moveFile(file, dest + "/Full_Scans")
  } // END mvFileScans()

  /** moveFile is already in FileFun */
/*
  private[vol] def moveFile(file: String, dest: String) = {

    Files.move(Paths.get(file), Paths.get(dest), REPLACE_EXISTING)

  }// END moveFile()
*/

  // move body
  // move evt
  // move report
  // move files w/ scans printed into them:
  // envars
  // modules
  // dumped registry


} // END CleanUp()

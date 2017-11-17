package com.bbs.vol.utils
import java.io.{File, PrintWriter}
import io.Source

/** Interface for common file operations. */
trait FileFun {

  private[vol] def writeToFile(fileName: String, data: String) = {
    val writer = new PrintWriter(new File(fileName))

    /** Write CSV to a file. */
    writer.write(data)
    writer.close()
  } // END writeToFile

  /** Should probably make string generic. */
  private[vol] def writeToFile(fileName: String, data: IndexedSeq[String]) = {

    val writer = new PrintWriter(new File(fileName))
    val dataStr = data.mkString("\n")

    /** Write CSV to a file. */
    writer.write(dataStr)
    writer.close()
  } // END writeToFile()

  /**
    * Read a file and tranform or filter it
    * Use readFileTransform("filename.txt")(x => x.toLowerCase)
    */
  private[vol] def readFileTransform(fileName: String)(f: Iterator[String] => Iterator[String]): Vector[String] = {
    val src = Source.fromFile( fileName )
    val lines = src.getLines
    val read = f(lines).toVector
    src.close
    return read
  } // END readFileTransform

  /** Read a file and put the lines in a Vector */
  private[vol] def readFileToVec(fileName: String): Vector[String] = {

    val src = Source.fromFile( fileName )

    val read = src.getLines.toVector

    src.close
    return read
  } // END readFileToVec()

} // END FileFun

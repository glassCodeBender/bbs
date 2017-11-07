package com.bbs.vol.windows

import scala.io.Source

/**
  * @author J. Alexander
  *         Purpose: Parses the output from volatility into a more usable format.
  */
trait VolParse {

  /************* UTILITY METHODS TO MAKE VALUES IN MODULE OUTPUTS ACCESSIBLE ***********/
  /**
    * parseOutput()
    * Remove the stuff we don't need from the output
    * @param volStr
    * @return Some[List[String]]
    */
  private[windows] def parseOutputDash(volStr: String): Option[List[String]] = {
    Some(
      Source.fromString(volStr)
        .getLines
        .dropWhile( !_.contains("------") )
        .dropWhile( _.contains("-----") )
        .map(_.trim)
        .toList
    )
  } // END parseOutput()
  private[windows] def parseOutputDashStr(volStr: String): Option[String] = {
    Some(
      Source.fromString(volStr).getLines
        .dropWhile( !_.contains("------") )
        .dropWhile( _.contains("-----") ).mkString
    )
  } // END parseOutput()

  private[windows] def parseOutputDashVec(volStr: String): Option[Vector[String]] = {
    Some(
      Source.fromString(volStr)
        .getLines
        .dropWhile( !_.contains("------") )
        .dropWhile( _.contains("-----") )
        .map(_.trim)
        .toVector
    )
  } // END parseOutput()

  private[windows] def parseOutputNoHeader(volStr: String): Option[Vector[String]] = {
    Some(
      Source.fromString(volStr)
        .getLines
        .map(_.trim)
        .toVector
    )
  } // END parseOutput()

  private[windows] def parseOutputAsterisks(volStr: String): Option[Vector[String]] = {
    Some(
      Source.fromString(volStr)
        .getLines
        .dropWhile( !_.contains("*******") )
        .dropWhile( _.contains("*******") )
        .map(_.trim)
        .toVector
    )
  } // END parseOutput()

  private[windows] def parseOutputDropHead(volStr: String): Option[List[String]] = {
    Some(
      Source.fromString(volStr)
        .getLines
        .map(_.trim)
        .toList
        .tail
    )
  } // END parseOutput()

  private[windows] def parseOutputArr(volStr: String): Option[Array[String]] = {
    Some(
      Source.fromString(volStr)
        .getLines
        .map(_.trim)
        .toArray
    )
  } // END parseOutput()

  private[windows] def parseOutputVec(volStr: String): Option[Vector[String]] = {
    Some( Source.fromString(volStr)
      .getLines
      .map(_.trim)
      .toVector
    )
  } // END parseOutput()
  private[windows] def parseOutputNoTrim(volStr: String): Option[Vector[String]] = {
    Some(
      Source.fromString(volStr)
        .getLines
        .toVector
    )
  } // parseOutputNoTrim()

  /**
    * seqParse(), vecParse(), arrParse()
    * Take an Seq, split each and we get get a Seq of Seqs.
    * These methods make it easier to pull data out of the results.
    * @param volStrVector
    * @return Option[List[Vector[String]]]
    */
  private[windows] def seqParse( volStrVector: List[String] ): Option[List[Vector[String]]] = {
    val splitResult = Some(volStrVector.map( _.split("\\s+").toVector ))

    return splitResult
  } // END seqParse()

  private[windows] def vecParse( volStrVector: Vector[String] ): Option[Vector[Vector[String]]] = {
    val splitResult = Some(volStrVector.map( _.split("\\s+").toVector ))

    return splitResult
  } // END seqParse()

  private[windows] def arrParse( volStrVector: Array[String] ): Option[Array[Vector[String]]] = {
    val splitResult = Some(volStrVector.map( _.split("\\s+").toVector ))

    return splitResult
  } // END seqParse()

} // END VolParse trait


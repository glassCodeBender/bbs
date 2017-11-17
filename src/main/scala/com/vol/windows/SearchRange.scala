package com.bbs.vol.utils

import scala.util.Try

trait SearchRange {

  /** Putting this off until I need it */
  private[vol] def seachIpRange(value: String, start: String, end: String): Boolean = {
    if(ipToLong(start) to ipToLong(end) contains ipToLong(value)) true
    else false

  } // END ipRange()

  private[this] def ipToLong(value: String): Long = {

    // should have three index locations.
    val arrValues: Array[String] = value.trim.split('.')
    val convertToLong: Array[Long] = arrValues.map(x => Try(x.toLong).getOrElse(0L))
    // 192.160.210.111 1.1.1.1
    if(value.length > 15 | value.length < 7) {
      println(s"WARNING: $value is an invalid IP address. Range search failed in convertIpToLong().\n")
    }

    val convertBack = convertToLong.map(x => x.toString)
    /** Since we're using this to check ranges of IPs, I concatenated strings. */
    val result = convertBack.foldLeft("")((x, y) => x + y)

    return result.toLong
  } // END ipToBytes()

  def searchHexRange(value: String, start: String, end: String): Boolean = {
    val bool = searchRange(hex2Long(value), hex2Long(start), hex2Long(end))

    return bool
  } // END hexRange()
  def searchHexRange(value: String, start: Long, end: Long): Boolean = {
    val bool = start to end contains hex2Long(value)
    return bool
  }
  def searchHexRange(value: Long, start: Long, end: Long): Boolean = {

    val bool = searchRange(value, start, end)

  return bool
  }
  def searchHexRange(value: Long, start: String, end: String): Boolean = {

    val bool = searchRange(value, hex2Long(start), hex2Long(end))

    return bool
  }

  private[this] def searchRange(value: Long, start: Long, end: Long) = {
    if (start to end contains value) true
    else false
  } // END

  /** convert hex memory location to an integer. */
  private[this] def hex2Long(hex: String): Long = {
    val bigInt = Integer.parseInt(hex.drop(2), 16)
    bigInt.longValue()
    // hex.toList.map("0123456789abcdef".indexOf(_)).reduceLeft(_ * 16 + _)
  } // END hex2Long

} // END SearchRange trait

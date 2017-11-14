package com.bbs.vol.httpclient

import java.net.{HttpURLConnection, URL}

trait HttpClient{

  def queryPage(url: String, connectTimeOut: Int = 5000,
            readTimeout: Int = 5000,
            request: String = "GET" ): String = {
    val page = grabPage(url, connectTimeOut, readTimeout, request)

   return page
  } // END query()

  /** Get web page */
  private[this] def grabPage(url: String,
                             connectTime: Int,
                             readTime: Int,
                             request: String): String = {
    val connection = new URL(url).openConnection.asInstanceOf[HttpURLConnection]

    connection.setConnectTimeout(connectTime)
    connection.setReadTimeout(readTime)
    connection.setRequestMethod(request)

    val inputStream = connection.getInputStream
    val webPage: String = io.Source.fromInputStream(inputStream).mkString
    if (inputStream == null) inputStream.close()

    return webPage
  } // END grabPage()

} // END Client


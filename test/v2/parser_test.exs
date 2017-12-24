defmodule ProxyProtocol.V2.ParserTest do
  use ExUnit.Case, async: true

  describe "TCP4 SUCCESS" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 17>>
      length = <<0, 12>>
      src_address = <<127, 0, 0, 1>>
      dest_address = <<192, 168, 0, 1>>
      src_port = <<1, 187>>
      dest_port = <<1, 187>>
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> src_address <> dest_address <> src_port <> dest_port

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "192.168.0.1",
          dest_port: 443,
          inet: "TCP4",
          src_address: "127.0.0.1",
          src_port: 443,
          version: "2"
        }
      }} = result)
    end
  end

  describe "UDP4 SUCCESS" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 18>>
      length = <<0, 12>>
      src_address = <<127, 0, 0, 1>>
      dest_address = <<192, 168, 0, 1>>
      src_port = <<1, 187>>
      dest_port = <<1, 187>>
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> src_address <> dest_address <> src_port <> dest_port

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "192.168.0.1",
          dest_port: 443,
          inet: "TCP4",
          src_address: "127.0.0.1",
          src_port: 443,
          version: "2"
        }
      }} = result)
    end
  end

  describe "TCP6 SUCCESS" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 33>>
      length = <<0, 36>>
      src_address = <<32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
      dest_address = <<32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
      src_port = <<1, 187>>
      dest_port = <<1, 188>>
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> src_address <> dest_address <> src_port <> dest_port

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "2001:0db8:0001:0000:0000:0000:0000:0000",
          dest_port: 444,
          inet: "TCP6",
          src_address: "2001:0db8:0001:0000:0000:0000:0000:0000",
          src_port: 443,
          version: "2"
        }
      }} = result)
    end
  end

  describe "UDP6 SUCCESS" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 34>>
      length = <<0, 36>>
      src_address = <<32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
      dest_address = <<32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
      src_port = <<1, 187>>
      dest_port = <<1, 188>>
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> src_address <> dest_address <> src_port <> dest_port

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "2001:0db8:0001:0000:0000:0000:0000:0000",
          dest_port: 444,
          inet: "TCP6",
          src_address: "2001:0db8:0001:0000:0000:0000:0000:0000",
          src_port: 443,
          version: "2"
        }
      }} = result)
    end
  end

  describe "STREAM SUCCESS" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 49>>
      length = <<0, 216>>
      src_address = "/var/pgsql_sock" <> <<0>> <> String.duplicate("0", 92)
      dest_address = "/var/pgsql_sock" <> <<0>> <> String.duplicate("0", 92)
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> src_address <> dest_address

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "/var/pgsql_sock",
          dest_port: nil,
          inet: "AF_UNIX",
          src_address: "/var/pgsql_sock",
          src_port: nil,
          version: "2"
        }
      }} = result)
    end
  end

  describe "DGRAM SUCCESS" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 50>>
      length = <<0, 216>>
      src_address = "/var/mysql_sock" <> <<0>> <> String.duplicate("0", 92)
      dest_address = "/var/mysql_sock" <> <<0>> <> String.duplicate("0", 92)
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> src_address <> dest_address

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "/var/mysql_sock",
          dest_port: nil,
          inet: "AF_UNIX",
          src_address: "/var/mysql_sock",
          src_port: nil,
          version: "2"
        }
      }} = result)
    end
  end

  describe "UNSPECIFIED with null byte" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 0>>
      length = <<0, 12>>
      skip = <<127, 0, 0, 1, 192, 168, 0, 11, 1, 187, 1, 187>>
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> skip

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: nil,
          dest_port: nil,
          inet: "UNSPECIFIED",
          src_address: nil,
          src_port: nil,
          version: "2"
        }
      }} = result)
    end
  end

  describe "UNRECOGNIZED" do
    setup do
      header = <<10, 13, 10, 13, 0, 10, 13, 81, 85, 73, 84, 10, 1>>
      length = <<0, 12>>
      skip = <<127, 0, 0, 1, 192, 168, 0, 11, 1, 187, 1, 187>>
      request = """
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """
      proxy = header <> length <> skip

      {:ok, packet: proxy <> request}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V2.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: nil,
          dest_port: nil,
          inet: "UNSPECIFIED",
          src_address: nil,
          src_port: nil,
          version: "2"
        }
      }} = result)
    end
  end
end
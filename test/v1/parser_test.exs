defmodule ProxyProtocol.V1.ParserTest do
  use ExUnit.Case, async: true

  describe "PROXY TCP4 SUCCESS" do
    setup do
      packet = """
      PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """

      {:ok, packet: packet}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V1.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "192.168.0.11",
          dest_port: 443,
          inet: "TCP4",
          src_address: "192.168.0.1",
          src_port: 56324,
          version: "1"
        }
      }} = result)
    end
  end

  describe "PROXY TCP4 IP FAILURE" do
    setup do
      packet = """
      PROXY TCP4 192.1638.0.1 192.168.0.11 56324 443\r
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """

      {:ok, packet: packet}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V1.Parser.parse(context[:packet])

      assert({:error, %{
        buffer: "192.1638.0.1 192.168.0.11 56324 443\r\nGET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: nil,
          dest_port: nil,
          inet: "TCP4",
          src_address: nil,
          src_port: nil,
          version: "1"
        }
      }} = result)
    end
  end

  describe "PROXY TCP6 SUCCESS" do
    setup do
      packet = """
      PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 443\r
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """

      {:ok, packet: packet}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V1.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "2001:0db8:0000:0042:0000:8a2e:0370:7335",
          dest_port: 443,
          inet: "TCP6",
          src_address: "2001:0db8:0000:0042:0000:8a2e:0370:7334",
          src_port: 4124,
          version: "1"
        }
      }} = result)
    end
  end

  describe "PROXY TCP6 IP FAILURE" do
    setup do
      packet = """
      PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:00;0:0042:0000:8a2e:0370:7335 4124 443\r
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """

      {:ok, packet: packet}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V1.Parser.parse(context[:packet])

      assert({:error, %{
        buffer: "2001:0db8:00;0:0042:0000:8a2e:0370:7335 4124 443\r\nGET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: nil,
          dest_port: nil,
          inet: "TCP6",
          src_address: "2001:0db8:0000:0042:0000:8a2e:0370:7334",
          src_port: nil,
          version: "1"
        }
      }} = result)
    end
  end

  describe "PROXY TCP6 PORT FAILURE" do
    setup do
      packet = """
      PROXY TCP6 2001:0db8:0000:0042:0000:8a2e:0370:7334 2001:0db8:0000:0042:0000:8a2e:0370:7335 4124 foo\r
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """

      {:ok, packet: packet}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V1.Parser.parse(context[:packet])

      assert({:error, %{
        buffer: "foo\r\nGET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: "2001:0db8:0000:0042:0000:8a2e:0370:7335",
          dest_port: nil,
          inet: "TCP6",
          src_address: "2001:0db8:0000:0042:0000:8a2e:0370:7334",
          src_port: 4124,
          version: "1"
        }
      }} = result)
    end
  end

  describe "PROXY UNKNOWN with extra chars" do
    setup do
      packet = """
      PROXY UNKNOWN 4124 443\r
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """

      {:ok, packet: packet}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V1.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: nil,
          dest_port: nil,
          inet: "UNKNOWN",
          src_address: nil,
          src_port: nil,
          version: "1"
        }
      }} = result)
    end
  end

  describe "PROXY UNKNOWN that ends with carriage return line feed" do
    setup do
      packet = """
      PROXY UNKNOWN\r
      GET / HTTP/1.1\r
      Host: 192.168.0.11\r
      \r
      """

      {:ok, packet: packet}
    end

    test "returns information about the proxy", context do
      result = ProxyProtocol.V1.Parser.parse(context[:packet])

      assert({:ok, %{
        buffer: "GET / HTTP/1.1\r\nHost: 192.168.0.11\r\n\r\n",
        proxy: %ProxyProtocol{
          dest_address: nil,
          dest_port: nil,
          inet: "UNKNOWN",
          src_address: nil,
          src_port: nil,
          version: "1"
        }
      }} = result)
    end
  end
end
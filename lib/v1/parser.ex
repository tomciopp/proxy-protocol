defmodule ProxyProtocol.V1.Parser do
  @moduledoc """
  Handles the plain text version of the proxy protocol as defined in section 2.1:
  https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

  This module builds up the ProxyProtocol struct attributes as we read
  the PROXY line.

  buffer represents the current state of the packet as it is being parsed

  This implementation is designed to be monadic and exhaustive,
  if there is an error we continue to pass through each function
  until we unwrap at the end with the result.

  """

  @space <<32>>
  @crlf <<13, 10>>
  @port_range 0..65535

  def parse(packet) do
    %{buffer: packet, proxy: %ProxyProtocol{version: "1"}}
    |> inet()
    |> address(:src_address)
    |> address(:dest_address)
    |> port(:src_port)
    |> port(:dest_port)
    |> result()
  end

  defp inet(%{buffer: buffer, proxy: proxy}), do: inet(buffer, proxy)
  defp inet(<<"PROXY TCP4 ", new_buffer :: binary>>, proxy) do
    %{buffer: new_buffer, proxy: Map.put(proxy, :inet, "TCP4")}
  end

  defp inet(<<"PROXY TCP6 ", new_buffer :: binary>>, proxy) do
    %{buffer: new_buffer, proxy: Map.put(proxy, :inet, "TCP6")}
  end

  defp inet(<<"PROXY UNKNOWN", new_buffer :: binary>>, proxy) do
    {:ok, %{buffer: drop_line(new_buffer), proxy: Map.put(proxy, :inet, "UNKNOWN")}}
  end

  defp inet(buffer, proxy), do: {:error, %{buffer: buffer, proxy: proxy}}

  defp address(%{buffer: buffer, proxy: proxy}, key), do: address(buffer, proxy, key)
  defp address(other, _key), do: other

  defp address(buffer, %ProxyProtocol{inet: "TCP4"} = proxy, key) do
    case ipv4(buffer) do
      {:ok, {address, new_buffer}} ->
        %{buffer: new_buffer, proxy: Map.put(proxy, key, address)}
      {:error, reason} ->
        {:error, %{buffer: buffer, proxy: proxy, reason: reason}}
    end
  end

  defp address(buffer, %ProxyProtocol{inet: "TCP6"} = proxy, key) do
    case ipv6(buffer) do
      {:ok, {address, new_buffer}} ->
        %{buffer: new_buffer, proxy: Map.put(proxy, key, address)}
      {:error, reason} ->
        {:error, %{buffer: buffer, proxy: proxy, reason: reason}}
    end
  end

  defp port(%{buffer: buffer, proxy: proxy}, key), do: port(buffer, proxy, key)
  defp port(other, _key), do: other

  defp port(buffer, proxy, key) do
    case find_port(buffer) do
      {:ok, {port, new_buffer}} ->
        %{buffer: new_buffer, proxy: Map.put(proxy, key, port)}
      {:error, reason} ->
        {:error, %{buffer: buffer, proxy: proxy, reason: reason}}
    end
  end

  defp result(map) when is_map(map), do: {:ok, map}
  defp result(other), do: other

  # IPv4 can be in the range of 0.0.0.0 - 255.255.255.255
  defp ipv4(<<ip :: binary-size(7), @space, buffer :: binary>>),  do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(8), @space, buffer :: binary>>),  do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(9), @space, buffer :: binary>>),  do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(10), @space, buffer :: binary>>), do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(11), @space, buffer :: binary>>), do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(12), @space, buffer :: binary>>), do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(13), @space, buffer :: binary>>), do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(14), @space, buffer :: binary>>), do: valid?(ip, buffer)
  defp ipv4(<<ip :: binary-size(15), @space, buffer :: binary>>), do: valid?(ip, buffer)
  defp ipv4(_no_match), do: {:error, "Buffer does not match ipv4 format"}

  # IPv6 format is 8 groups of 4 digit hex chars separated by colon
  # ex: 2001:0db8:0000:0042:0000:8a2e:0370:7334
  defp ipv6(<<ip :: binary-size(39), @space, buffer :: binary>>), do: valid?(ip, buffer)
  defp ipv6(_no_match), do: {:error, "Buffer does not match ipv6 format"}

  defp valid?(ip, buffer) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, _valid} -> {:ok, {ip, buffer}}
      {:error, _reason} -> {:error, "This is not a valid ip address"}
    end
  end

  # Ports can be in the range of [0..65535]
  defp find_port(<<port :: binary-size(1), @crlf, buffer :: binary>>),  do: port?(port, buffer)
  defp find_port(<<port :: binary-size(2), @crlf, buffer :: binary>>),  do: port?(port, buffer)
  defp find_port(<<port :: binary-size(3), @crlf, buffer :: binary>>),  do: port?(port, buffer)
  defp find_port(<<port :: binary-size(4), @crlf, buffer :: binary>>),  do: port?(port, buffer)
  defp find_port(<<port :: binary-size(5), @crlf, buffer :: binary>>),  do: port?(port, buffer)
  defp find_port(<<port :: binary-size(1), @space, buffer :: binary>>), do: port?(port, buffer)
  defp find_port(<<port :: binary-size(2), @space, buffer :: binary>>), do: port?(port, buffer)
  defp find_port(<<port :: binary-size(3), @space, buffer :: binary>>), do: port?(port, buffer)
  defp find_port(<<port :: binary-size(4), @space, buffer :: binary>>), do: port?(port, buffer)
  defp find_port(<<port :: binary-size(5), @space, buffer :: binary>>), do: port?(port, buffer)
  defp find_port(_no_match), do: {:error, "Buffer does not match port format"}

  defp port?(port, buffer) do
    try do
      case Enum.member?(@port_range, String.to_integer(port)) do
        true -> {:ok, {String.to_integer(port), buffer}}
        false -> {:error, "Port needs to be between 0 and 65535"}
      end
    rescue
      ArgumentError -> {:error, "Could not parse port"}
    end
  end

  defp drop_line(buffer) do
    buffer |> String.splitter(@crlf) |> Stream.drop(1) |> Enum.join(@crlf)
  end
end

defmodule ProxyProtocol.Mixfile do
  use Mix.Project

  def project do
    [
      app: :proxy_protocol,
      version: "0.0.1",
      elixir: "~> 1.5",
      start_permanent: Mix.env == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, ">= 0.0.0", only: :dev}
    ]
  end

  defp description do
    """
    A parser for version 1 and 2 of HAProxy's proxy protocol.
    """
  end

  defp package do
    [
      maintainers: ["tomciopp"],
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/tomciopp/proxy-protocol"}
    ]
  end
end

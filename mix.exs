defmodule ExWebauthn.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/niquixorg/ex_webauthn"

  def project do
    [
      app: :ex_webauthn,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Elixir NIF wrapper for webauthn-rs",
      source_url: @source_url,
      homepage_url: @source_url,
      package: package(),
      docs: docs(),
      dialyzer: [plt_add_apps: [:mix]]
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.37", runtime: false},
      {:rustler_precompiled, "~> 0.8"},
      {:jason, "~> 1.4"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      name: "ex_webauthn",
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib native .formatter.exs mix.exs README.md LICENSE checksum-*.exs)
    ]
  end

  defp docs do
    [
      main: "ExWebauthn",
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end
end

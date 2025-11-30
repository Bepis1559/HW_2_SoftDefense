
namespace PluginHost
{
    internal interface IPlugin
    {
        string Name { get; }
        void Execute(string input);
    }
}

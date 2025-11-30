
namespace SafeHost
{
    public interface IPlugin
    {
        string Name { get; }
        void Execute(string input);
    }
}
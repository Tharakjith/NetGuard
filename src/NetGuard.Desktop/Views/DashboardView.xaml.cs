using System.Windows.Controls;
using System.Windows.Input;
using NetGuard.Desktop.ViewModels;

namespace NetGuard.Desktop.Views;

public partial class DashboardView : UserControl
{
    public DashboardView() => InitializeComponent();

    private void OnApplicationDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is DashboardViewModel vm && Apps.SelectedItem is not null)
        {
            vm.OpenApplicationCommand.Execute(Apps.SelectedItem);
        }
    }
}

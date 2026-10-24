from django.db import migrations, models


def rename_circus(apps, schema_editor):
    Operator = apps.get_model("accounts", "Operator")
    Operator.objects.filter(theme="circus").update(theme="cozy")


def rename_cozy(apps, schema_editor):
    Operator = apps.get_model("accounts", "Operator")
    Operator.objects.filter(theme="cozy").update(theme="circus")


class Migration(migrations.Migration):

    dependencies = [("accounts", "0004_operator_theme")]

    operations = [
        migrations.AlterField(
            model_name="operator",
            name="theme",
            field=models.CharField(
                choices=[("default", "Default"), ("cozy", "Cozy Clown"), ("obnoxious", "Obnoxious Clown")],
                default="default",
                max_length=16,
            ),
        ),
        migrations.RunPython(rename_circus, rename_cozy),
    ]

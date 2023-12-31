# Generated by Django 4.1 on 2023-12-02 07:15

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='deposit',
            old_name='berat',
            new_name='total_price',
        ),
        migrations.RenameField(
            model_name='deposit',
            old_name='totalHarga',
            new_name='weight',
        ),
        migrations.RemoveField(
            model_name='deposit',
            name='jenis',
        ),
        migrations.RemoveField(
            model_name='withdraw',
            name='jumlah',
        ),
        migrations.AddField(
            model_name='deposit',
            name='waste_type',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='prize',
            name='picture',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='userdata',
            name='token',
            field=models.CharField(default='KSUJZEG', max_length=6, unique=True),
        ),
        migrations.AddField(
            model_name='withdraw',
            name='account_no',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='withdraw',
            name='amount',
            field=models.BigIntegerField(default=0),
        ),
        migrations.AddField(
            model_name='withdraw',
            name='method',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='withdraw',
            name='provider',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='deposit',
            name='date',
            field=models.DateField(default=django.utils.timezone.now),
        ),
        migrations.AlterField(
            model_name='deposit',
            name='username',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='redeemedprize',
            name='desc',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='redeemedprize',
            name='title',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='username',
            field=models.CharField(max_length=150, unique=True),
        ),
        migrations.AlterField(
            model_name='withdraw',
            name='date',
            field=models.DateField(default=django.utils.timezone.now),
        ),
    ]

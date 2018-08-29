# aspnetcore-jwt-boilerplate
Boiler-plate for aspnetcore identity with JWT authentication . Bootstrapped with EF Core database first , and hybrid Dapper ORM for data retrieval 

# setup
'Add-Migration Init' and 'Update-Database' in Core 

'Scaffold-DbContext "Data Source=<source>;Initial Catalog=<db name>;integrated security=True;MultipleActiveResultSets=True;" Microsoft.EntityFrameworkCore.SqlServer -OutputDir Models -f'
in DAL project 

Resolve dependancy injection in Startup 

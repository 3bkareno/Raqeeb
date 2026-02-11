using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Raqeeb.Infrastructure.Persistence.Migrations
{
    /// <inheritdoc />
    public partial class AddComplianceMappingFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CvssScore",
                table: "Vulnerabilities",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CweId",
                table: "Vulnerabilities",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "OwaspCategory",
                table: "Vulnerabilities",
                type: "nvarchar(max)",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CvssScore",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "CweId",
                table: "Vulnerabilities");

            migrationBuilder.DropColumn(
                name: "OwaspCategory",
                table: "Vulnerabilities");
        }
    }
}

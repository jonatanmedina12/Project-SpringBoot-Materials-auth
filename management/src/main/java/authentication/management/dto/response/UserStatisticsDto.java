package authentication.management.dto.response;

public class UserStatisticsDto {
    private final Long totalUsers;
    private final Long activeUsers;
    private final Long adminUsers;
    private final Long regularUsers;

    public UserStatisticsDto(Long totalUsers, Long activeUsers, Long adminUsers, Long regularUsers) {
        this.totalUsers = totalUsers;
        this.activeUsers = activeUsers;
        this.adminUsers = adminUsers;
        this.regularUsers = regularUsers;
    }

    // Getters
    public Long getTotalUsers() {
        return totalUsers;
    }

    public Long getActiveUsers() {
        return activeUsers;
    }

    public Long getAdminUsers() {
        return adminUsers;
    }

    public Long getRegularUsers() {
        return regularUsers;
    }
}
